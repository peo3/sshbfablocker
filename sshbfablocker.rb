#!/usr/bin/env ruby

require 'thread'
require 'syslog'
require 'optparse'
require "stringio"

class File
	def each_appended
		self.seek(0, IO::SEEK_END)
		befsize = self.stat.size

		loop do
			sleep 1
			size = self.stat.size
			if size > befsize
				io = StringIO.new(self.sysread(size - befsize))
				while line = io.gets
					yield line
				end

				befsize = size
			end
		end
	end
end

class AttackMonitor
	def initialize( sshlogfile, whitelist, q )
		@sshlogfile = sshlogfile
		@whitelist = whitelist || []
		@q = q

		@th = nil
	end

	def whitelist?( ip )
		@whitelist.each do |white|
			return true if ip.include? white
		end
		false
	end

	def ssh_bfa?( log )
		["Invalid", "Illegal", "Failed"].each do |str|
			return true if log.include? str and log.include? "sshd"
		end
		false
	end

	def start_thread
		@th = Thread.start do
			f = File.open(@sshlogfile)
			Thread.current[:file] = f
			f.each_appended do |line|
				next unless ssh_bfa? line
				next if line.include? SSHBFABlocker::IDENTIFIER

				if line =~ /from (\d{1,3}(\.\d{1,3}){3})/
					ip = $1

					# pass to the blocker thread
					@q.push ip unless whitelist? ip
				end
			end
		end
	end

	def reopen_monitoringfile
		@th.terminate
		@th[:file].close unless @th[:file].closed?
		start_thread
	end

end # class AttackMonitor

class SSHBFABlocker
	BLOCK_PERIODS = 60*3
	IDENTIFIER = "sshbfablocker"
	PID_FILE = "/var/run/#{IDENTIFIER}.pid"
	VERSION = "20071210"

	def initialize( sshlogfile, whitelist=[], daemonize=false )
		@daemonize = daemonize

		@blocked = []
		@q = Queue.new
		@mutex = Mutex.new

		@monitor = AttackMonitor.new(sshlogfile, whitelist, @q)
	end

	def logging( msg )
		if @daemonize
			Syslog.warning("%s", msg)
		else
			puts msg
		end
	end

	# this code from http://www.freedom.ne.jp/toki/ruby.html
	def daemonize!
		catch(:RUN_DAEMON) do
			unless fork then
				Process::setsid
				unless fork then
					Dir::chdir("/")
					File::umask(0)
					STDIN.close
					STDOUT.close
					STDERR.close
					throw :RUN_DAEMON
				end
			end
			exit!
		end
	end

	def do_block( ip )
		system("iptables -I INPUT -p tcp -s #{ip} --dport 22 -j REJECT")
		logging("#{ip} is blocked.")
	end
	def do_unblock( ip )
		system("iptables -D INPUT -p tcp -s #{ip} --dport 22 -j REJECT")
		logging("#{ip} is unblocked.")
	end

	def start_blocker_thread
		Thread.start do
			loop do
				ip = @q.pop

				already_blocked = false
				@mutex.synchronize {
					if @blocked.include? ip
						already_blocked = true
					else
						@blocked << ip
					end
				}
				next if already_blocked

				Thread.start(ip) do |ip1|
					do_block(ip1)
			
					sleep BLOCK_PERIODS

					do_unblock(ip1)

					@mutex.synchronize {
						@blocked.delete ip1
					}
				end
			end
		end
	end

	def hup
		@monitor.reopen_monitoringfile
		Syslog.close 
		Syslog.open(IDENTIFIER, nil, Syslog::LOG_AUTHPRIV)
		logging("reopen the monitoring file.")
	end

	def start
		if @daemonize
			daemonize!
			open(PID_FILE, "w+") {|f| f.print Process.pid }
			$0 = "#{IDENTIFIER}.rb: [daemonized]"
			Syslog.open(IDENTIFIER, nil, Syslog::LOG_AUTHPRIV)
		end

		start_blocker_thread
		@monitor.start_thread

		logging("started.")
		Thread.stop
		# never reached
	end

	def stop
		@blocked.each do |ip|
			do_unblock(ip)
		end
		logging("stopped.")
		if @daemonize
			File.delete(PID_FILE) if File.exist? PID_FILE
			Syslog.close 
		end
	end
end


if $0 == __FILE__
	Thread.abort_on_exception = true

	OPTS = {}
	OptionParser.new do |opt|
		opt.banner = "usage: #{File.basename($0)} [options] sshlogfile"
		Version = SSHBFABlocker::VERSION

		opt.on('-w VAL', '--whitelist=VAL',
			"list of IP addresses separated by ','.", 'e.g. "192.168.0.1,192.168.1.".') {|v|
			OPTS[:whitelist] = v.split(',')
		}
		opt.on('--daemon', 'run as daemon.') {|v|
			OPTS[:daemon] = true
		}
		opt.parse!(ARGV)

		unless ARGV.size == 1
			abort opt.help
		end
	end

	sshlogfile = ARGV[0]

	blocker = SSHBFABlocker.new(sshlogfile, OPTS[:whitelist], OPTS[:daemon])

	if OPTS[:daemon]
		Signal.trap(:TERM) do
			blocker.stop
			exit
		end
	else
		Signal.trap(:INT) do
			blocker.stop
			exit
		end
	end
	Signal.trap(:HUP) do
		blocker.hup
	end

	blocker.start
end


