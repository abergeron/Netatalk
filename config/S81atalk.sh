#!/bin/sh
# netatalk	  Netatalk 2.x initscript

# load synology module action function
. /etc.defaults/rc.subr

AFPD=/usr/syno/sbin/afpd
NETATALK_CONF=/usr/syno/etc/netatalk
PIDPATH=/var/run

# Guard to prevent execution if netatalk was removed.
if ! [ -x $AFPD ]; then
	logger -p err -t Netatalk "$AFPD is not executable !"
	exit $LSB_ERR_INSTALLED
fi

# Set defaults. Please change these options in /usr/syno/etc/netatalk
ATALK_NAME=`/bin/hostname`
ATALK_ZONE=

KERNELMODULE="appletalk"
AFPD_MAX_CLIENTS=256
AFPD_GUEST=guest
AFPD_HOST="`/bin/hostname| /bin/sed 's/\..*$//'`:AFPServer"
AFPD_LOGOPT="default log_error"
# original netatalk 2.2 setting
#AFPD_HOST=${ATALK_NAME}${ATALK_ZONE}
CNID_CONFIG="-l log_error"

ATALKD_RUN=no
PAPD_RUN=no
TIMELORD_RUN=no
ATALK_BGROUND=no
CNID_METAD_RUN=yes
AFPD_RUN=yes
AFPD_ENABLED=`/bin/get_key_value /etc/synoinfo.conf runafp`

set_afpd_affinity() {
	uname -a | grep -i qoriq > /dev/null 2>&1
	local isQorIQ="$?"

	if [ 0 -eq ${isQorIQ} ]; then
		for each_pid in `/bin/pidof afpd`; do
			/usr/bin/taskset -p 1 $each_pid > /dev/null 2>&1
		done
	fi
}

checkLogLevel()
{
	case "$1" in
		error|warning|note|info|debug|maxdebug)
		;;
		*)
		return
		;;
	esac
	if [ -z "$2" ]; then
		CNID_CONFIG="-l log_$1"
		AFPD_LOGOPT="default log_$1"
	else
		CNID_CONFIG="-l log_$1 -f $2"
		AFPD_LOGOPT="default log_$1 $2"
	fi
}

# Read in netatalk configuration.
if [ -f $NETATALK_CONF ]; then
	. $NETATALK_CONF
fi

# Start Netatalk servers.
atalk_startup() {
	#create log directory
	if [ ! -d /tmp/apple ]; then
		[ -e /tmp/apple ] && rm -f /tmp/apple;
		/bin/mkdir /tmp/apple;
		/bin/chmod 777 /tmp/apple;
	fi

	if [ -e /usr/syno/sbin/stress.sh ]; then
		echo "stress test! Do not run atalkd";
		ATALKD_RUN=no
	fi
	if [ "$ATALKD_RUN" = "yes" ]; then
		# Try to load the AppleTalk kernel module if it was intended.
		SYNOLoadModules $KERNELMODULE

		# Start atalkd server.
		/usr/syno/sbin/atalkd
		# register workstation
		/usr/syno/bin/nbprgstr -p 4 "$ATALK_NAME:Workstation$ATALK_ZONE"
		/usr/syno/bin/nbprgstr -p 4 "$ATALK_NAME:netatalk$ATALK_ZONE"

		echo -n " atalkd"
	fi
	
	if [ "$AFPD_ENABLED" = "yes" ]; then
		# prepare startup of file services
		if [ "$CNID_METAD_RUN" = "yes" -a -x /usr/syno/sbin/cnid_metad ] ; then
			echo -n " cnid_metad"
			/usr/syno/sbin/cnid_metad $CNID_CONFIG
		fi

		if [ "$AFPD_RUN" = "yes" ]; then
			$AFPD -g $AFPD_GUEST -c $AFPD_MAX_CLIENTS -n $AFPD_HOST -l "$AFPD_LOGOPT"

			{
				/bin/sleep 1
				set_afpd_affinity
			} &

			echo -n " afpd ($AFPD_HOST)"
		fi
	fi

	if [ "$ATALKD_RUN" = "yes" ]; then
		if [ "$PAPD_RUN" = "yes" ]; then
			/usr/syno/sbin/papd -f /usr/syno/etc/papd.conf -p /usr/syno/etc/printcap
			echo -n " papd"
		fi

		if [ "$TIMELORD_RUN" = "yes" ]; then
			/usr/syno/sbin/timelord
			echo -n " timelord"
		fi
	fi
}

kill_process()
{
	if pidof $1 >/dev/null; then
		echo -n " $1"
		killall -15 $1
		sleep 1
		if [ $? -ne 0 ]; then
			echo "Force kill -9 $1 !"
			killall -9 $1
			rm -f $PIDPATH/$1.pid
		fi
	fi
}

case "$1" in
	start)
		checkLogLevel $2 $3
		if [ "$ATALK_BGROUND" = "yes" -a "$ATALKD_RUN" = "yes" ]; then
			echo "Starting Netatalk services in the background."
			atalk_startup >/dev/null &
		else
			echo "Starting Netatalk services (this will take a while): "
			atalk_startup
			echo "."
		fi
	;;

	stop)
		echo "Stopping Netatalk Daemons:"

		kill_process afpd
		kill_process cnid_metad
		#kill_process papd
		#kill_process timelord
		#kill_process atalkd
		if lsmod| grep $KERNELMODULE >/dev/null; then
			SYNOUnloadModules $KERNELMODULE
		fi
	
		echo "."
	;;

	status)
		local ret=0

		lsb_status afpd
		ret=$?
		[ "$ret" -ne ${LSB_STAT_RUNNING} ] && exit $ret

		lsb_status cnid_metad
		exit $?
	;;
	
	restart)
		$0 force-reload $2 $3
	;;

	force-reload)
		echo "Restarting Netatalk Daemons (this will take a while)"
		$0 stop
		echo -n "."
		sleep 2
		echo -n "."
		if $0 start $2 $3; then
			echo "done."
		fi
	;;
  
	*)
		echo "Usage: $0 {start|stop|restart|force-reload}" >&2
		exit 1
	;;
esac
