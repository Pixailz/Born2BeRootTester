#!/bin/bash

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
#> Config

LOGIN=
MONITORING_PATH=

PROMPT_OFFSET=2
TITLE_LENGTH=80
# CHARACTER * N (BASH)
# https://stackoverflow.com/a/17030976
PROMPT_OFFSET=$(printf "%0.s " $(seq 1 ${PROMPT_OFFSET}))

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
#> Bash Color (printable)

red="\x1b[38;5;196m"
green="\x1b[38;5;82m"
blue="\x1b[38;5;75m"
orange="\x1b[38;5;214m"
blink="\x1b[5m"

reset="\x1b[0m"

SUCCESS="[${green}+${reset}] "
FAILED="[${red}-${reset}] "

UL="\xe2\x95\x94"
HO="\xe2\x95\x90"
UR="\xe2\x95\x97"
VE="\xe2\x95\x91"
LL="\xe2\x95\x9a"
LR="\xe2\x95\x9d"
HEART="\xe2\x99\xa5"

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
#> Utils

function check_root() {
	if [ ${EUID} != 0 ]; then
		p_error "Run as root."
	fi
}

function p_error() {
	printf "[${PROMPT_OFFSET}${red}ERROR${PROMPT_OFFSET}${reset}] $*\n"
	exit
}

function p_info() {
	printf "[${PROMPT_OFFSET}${blue}INFO${PROMPT_OFFSET}${reset}] $*\n"
}

function p_warn() {
	printf "[${PROMPT_OFFSET}${orange}WARN${PROMPT_OFFSET}${reset}] $*\n"
}

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
#> Monitoring check

function check_monitoring_prepare_sh() {
	#[ -f tmp ] && rm -rf tmp
	[ -d tmp ] && rm -rf tmp
	[ ! -d tmp ] && mkdir tmp
	if [ -f "${MONITORING_PATH}" ]; then
		moni_1=1
	else
		moni_1=0
		p_error "${MONITORING_PATH}"
	fi
	MONITORING_FILE=$(echo ${MONITORING_PATH} | sed -nE 's|.*/(.*)$|\1|p')
	cp ${MONITORING_PATH} ./tmp/
	sed -i "s|wall|echo|" ./tmp/${MONITORING_FILE}
	# append some output, at the end of the script
	sed -i 's|#Sudo:.*|\0 > ./tmp/output_user|' ./tmp/${MONITORING_FILE}
}

function check_cron_schedule() {
	crontab=$(sudo crontab -l 2>/dev/null | sed -nE "s|(.*)${MONITORING_PATH}$|\1|p")
	minute=$(echo "${crontab}" | cut -d' ' -f1)
	hour=$(echo "${crontab}" | cut -d' ' -f2)
	day_m=$(echo "${crontab}" | cut -d' ' -f3)
	month=$(echo "${crontab}" | cut -d' ' -f4)
	day_w=$(echo "${crontab}" | cut -d' ' -f5)
	cron_4=1
	[ "${minute}" != "*/10" ] && cron_4=0
	[ "${hour}" != "*" ] && cron_4=0
	[ "${day_m}" != "*" ] && cron_4=0
	[ "${month}" != "*" ] && cron_4=0
	[ "${day_w}" != "*" ] && cron_4=0
}

function check_have_cron() {
	# /var/spool/cron/crontabs/${LOGIN}
	crontab=$(sudo crontab -l 2>/dev/null | grep -v '^#')
	is_monitoring=$(echo "${crontab}" | cut -d' ' -f6-)
	is_monitoring=$(echo "${is_monitoring}" | grep -E '.*monitoring.*')
	[ ! -z "${crontab}" ] && cron_1=1 || cron_1=0
	[ ! -z "${is_monitoring}" ] && cron_2=1 || cron_2=0
	[ -f "${is_monitoring}" ] && cron_3=1 || cron_3=0
}

function check_crontab() {
	check_have_cron
	check_cron_schedule
}

function check_monitoring_test_sh() {
	./monitoring
	./tmp/${MONITORING_FILE}
	moni_base_arch=$(sed -nE 's|#Architecture:\s*(.*)|\1|Ip' ./tmp/output_base)
	moni_user_arch=$(sed -nE 's|#Architecture:\s*(.*)|\1|Ip' ./tmp/output_user)
	moni_base_cpup=$(sed -nE 's|#CPU PHYSICAL:\s*(.*)|\1|Ip' ./tmp/output_base)
	moni_user_cpup=$(sed -nE 's|#CPU PHYSICAL:\s*(.*)|\1|Ip' ./tmp/output_user)
	moni_base_cpuv=$(sed -nE 's|#vCPU:\s*(.*)|\1|Ip' ./tmp/output_base)
	moni_user_cpuv=$(sed -nE 's|#vCPU:\s*(.*)|\1|Ip' ./tmp/output_user)
	moni_base_ramu=$(sed -nE 's|#Memory usage:\s*(.*)|\1|Ip' ./tmp/output_base)
	moni_user_ramu=$(sed -nE 's|#Memory usage:\s*(.*)|\1|Ip' ./tmp/output_user)
	moni_base_disk=$(sed -nE 's|#Disk Usage:\s*(.*)|\1|Ip' ./tmp/output_base)
	moni_user_disk=$(sed -nE 's|#Disk Usage:\s*(.*)|\1|Ip' ./tmp/output_user)
	moni_base_cpul=$(sed -nE 's|#CPU Load:\s*(.*)|\1|Ip' ./tmp/output_base)
	moni_user_cpul=$(sed -nE 's|#CPU Load:\s*(.*)|\1|Ip' ./tmp/output_user)
	moni_base_last=$(sed -nE 's|#Last boot:\s*(.*)|\1|Ip' ./tmp/output_base)
	moni_user_last=$(sed -nE 's|#Last boot:\s*(.*)|\1|Ip' ./tmp/output_user)
	moni_base_lvmu=$(sed -nE 's|#LVM use:\s*(.*)|\1|Ip' ./tmp/output_base)
	moni_user_lvmu=$(sed -nE 's|#LVM use:\s*(.*)|\1|Ip' ./tmp/output_user)
	moni_base_tcpc=$(sed -nE 's|#Connection TCP:\s*(.*)|\1|Ip' ./tmp/output_base)
	moni_user_tcpc=$(sed -nE 's|#Connection TCP:\s*(.*)|\1|Ip' ./tmp/output_user)
	moni_base_user=$(sed -nE 's|#User log:\s*(.*)|\1|Ip' ./tmp/output_base)
	moni_user_user=$(sed -nE 's|#User log:\s*(.*)|\1|Ip' ./tmp/output_user)
	moni_base_netw=$(sed -nE 's|#Network:\s*(.*)|\1|Ip' ./tmp/output_base)
	moni_user_netw=$(sed -nE 's|#Network:\s*(.*)|\1|Ip' ./tmp/output_user)
	moni_base_sudo=$(sed -nE 's|#Sudo:\s*(.*)|\1|Ip' ./tmp/output_base)
	moni_user_sudo=$(sed -nE 's|#Sudo:\s*(.*)|\1|Ip' ./tmp/output_user)
}

function check_monitoring_compare() {
	[ "${moni_base_arch}" == "${moni_user_arch}" ] && moni_2=1 || moni_2=0
	[ "${moni_base_cpup}" == "${moni_user_cpup}" ] && moni_3=1 || moni_3=0
	[ "${moni_base_cpuv}" == "${moni_user_cpuv}" ] && moni_4=1 || moni_4=0
	[ "${moni_base_ramu}" == "${moni_user_ramu}" ] && moni_5=1 || moni_5=0
	[ "${moni_base_disk}" == "${moni_user_disk}" ] && moni_6=1 || moni_6=0
	[ "${moni_base_cpul}" == "${moni_user_cpul}" ] && moni_7=1 || moni_7=0
	[ "${moni_base_last}" == "${moni_user_last}" ] && moni_8=1 || moni_8=0
	[ "${moni_base_lvmu}" == "${moni_user_lvmu}" ] && moni_9=1 || moni_9=0
	[ "${moni_base_tcpc}" == "${moni_user_tcpc}" ] && moni_10=1 || moni_10=0
	[ "${moni_base_user}" == "${moni_user_user}" ] && moni_11=1 || moni_11=0
	[ "${moni_base_netw}" == "${moni_user_netw}" ] && moni_12=1 || moni_12=0
	[ "${moni_base_netw}" == "${moni_user_netw}" ] && moni_13=1 || moni_13=0
}

function check_monitoring() {
	# TODO add comparison with THRESHOLD, for accuracy at about 0.5
	check_crontab
	check_monitoring_prepare_sh
	check_monitoring_test_sh
	check_monitoring_compare
	[ -d ./tmp ] && rm -rf ./tmp
}

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
#> basic check

function check_lvm() {
	number_of_lvm=$(lsblk | grep "lvm" | wc -l)
	is_crypted=$(lsblk | grep "crypt" | wc -l)
	[ ${number_of_lvm} -ge 2 ] && lvm_1=1 || lvm_1=0
	[ ${is_crypted} -ge 1 ] && lvm_2=1 || lvm_2=0
}

function check_ssh() {
	is_installed=$(sudo systemctl list-units 2>/dev/null | grep -o ssh)
	ssh_port=$(sed -nE 's|^Port\s*(.*)$|\1|p' /etc/ssh/sshd_config 2>/dev/null)
	prohibit_root=$(sed -nE 's|^PermitRootLogin\s*(no)$|\1|p' /etc/ssh/sshd_config 2>/dev/null)
	[ ${is_installed} ] && ssh_1=1 || ssh_1=0
	[ "${ssh_port}" == 4242 ] && ssh_2=1 || ssh_2=0
	[ ${prohibit_root} ] && ssh_3=1 || ssh_3=0
}

function check_ufw() {
	is_installed=$(sudo which ufw 2>/dev/null)
	is_enabled=$(sudo ufw status  2>/dev/null | sed -nE 's|Status: (active)|\1|p')
	rule_1=$(sudo ufw status 2>/dev/null | sed -znE 's|.*4242.*(ALLOW).*|\1|p')
	rule_2=$(sudo ufw status 2>/dev/null | sed -znE 's|.*4242/(udp).*ALLOW.*|\1|p')
	[ ${is_installed} ] && ufw_1=1 || ufw_1=0
	[ ${is_enabled} ] && ufw_2=1 || ufw_2=0
	[ "${rule_1}" == "ALLOW" ] && ufw_3=1 || ufw_3=0
	[ "${rule_2}" == "udp" ] && ufw_4=0 || ufw_4=1
}

function check_hostname() {
	hostname="${LOGIN}42"
	hosts=$(sed -nE 's|127.0.0.1\t([a-z0-9\-]{1,63})|\1|p' /etc/hosts)
	[ "${hostname}" == $(hostname) ] && hostname_1=1 || hostname_1=0
	if [ "${hosts}" == "localhost" ]; then
		hosts2=$(sed -nE 's|127.0.1.1\t([a-z0-9\-]{1,63})|\1|p' /etc/hosts)
		[ "${hosts2}" == ${hostname} ] && hostname_2=1 || hostname_2=0
	else
		[ "${hosts}" == ${hostname} ] && hostname_2=1 || hostname_2=0
	fi
}

function check_strong_password() {
	is_installed=$(grep -o "pam_pwquality.so" /etc/pam.d/common-password 2>/dev/null)
	rule_user_max=$(sudo grep "${LOGIN}" /etc/shadow | cut -d":" -f5)
	rule_user_min=$(sudo grep "${LOGIN}" /etc/shadow | cut -d":" -f4)
	rule_user_warn=$(sudo grep "${LOGIN}" /etc/shadow | cut -d":" -f6)
	rule_new_max=$(sed -nE "s|PASS_MAX_DAYS.*(30).*|\1|p" /etc/login.defs 2>/dev/null)
	rule_new_min=$(sed -nE "s|PASS_MIN_DAYS.*(2).*|\1|p" /etc/login.defs 2>/dev/null)
	rule_new_warn=$(sed -nE "s|PASS_WARN_AGE.*(7).*|\1|p" /etc/login.defs 2>/dev/null)
	rule_min_char=$(sed -nE "s|.*minlen=(10).*|\1|p" /etc/pam.d/common-password 2>/dev/null)
	rule_upper=$(sed -nE "s|.*ucredit=(-1).*|\1|p" /etc/pam.d/common-password 2>/dev/null)
	rule_lower=$(sed -nE "s|.*lcredit=(-1).*|\1|p" /etc/pam.d/common-password 2>/dev/null)
	rule_digit=$(sed -nE "s|.*dcredit=(-1).*|\1|p" /etc/pam.d/common-password 2>/dev/null)
	rule_maxrepeat=$(sed -nE "s|.*maxrepeat=(3).*|\1|p" /etc/pam.d/common-password 2>/dev/null)
	rule_username=$(sed -nE "s|.*usercheck=([0-9]).*|\1|p" /etc/pam.d/common-password 2>/dev/null)
	rule_diff_old=$(sed -nE "s|.*difok=(7).*|\1|p" /etc/pam.d/common-password 2>/dev/null)
	rule_force_root=$(grep -o "enforce_for_root" /etc/pam.d/common-password 2>/dev/null)
	[ "${is_installed}" == "pam_pwquality.so" ] && pwquality_1=1 || pwquality_1=0
	[ "${rule_user_max}" == 30 ] && pwquality_2=1 || pwquality_2=0
	[ "${rule_user_min}" == 2 ] && pwquality_3=1 || pwquality_3=0
	[ "${rule_user_warn}" == 7 ] && pwquality_4=1 || pwquality_4=0
	[ "${rule_new_max}" == 30 ] && pwquality_5=1 || pwquality_5=0
	[ "${rule_new_min}" == 2 ] && pwquality_6=1 || pwquality_6=0
	[ "${rule_new_warn}" == 7 ] && pwquality_7=1 || pwquality_7=0
	[ "${rule_min_char}" ] && pwquality_8=1 || pwquality_8=0
	[ "${rule_upper}" ] && pwquality_9=1 || pwquality_9=0
	[ "${rule_lower}" ] && pwquality_10=1 || pwquality_10=0
	[ "${rule_digit}" ] && pwquality_11=1 || pwquality_11=0
	[ "${rule_maxrepeat}" ] && pwquality_12=1 || pwquality_12=0
	[ "${rule_username}" == 0 ] && pwquality_13=0 || pwquality_13=1
	[ "${rule_diff_old}" ] && pwquality_14=1 || pwquality_14=0
	[ "${rule_force_root}" ] && pwquality_15=1 || pwquality_15=0
}

function check_strict_sudo() {
	passwd_tries=$(sudo sed -nE 's|.*passwd_tries=(3).*|\1|p' /etc/sudoers 2>/dev/null)
	passwd_message=$(sudo sed -nE 's|.*badpass_message="(.+)".*|\1|p' /etc/sudoers 2>/dev/null)
	passwd_input=$(sudo sed -nE 's|Default.*(log_input).*|\1|p' /etc/sudoers 2>/dev/null)
	passwd_output=$(sudo sed -nE 's|Default.*(log_output).*|\1|p' /etc/sudoers 2>/dev/null)
	log_path="/var/log/sudo/sudo.log"
	passwd_log=$(sudo sed -nE "s|.*logfile=\"?(${log_path})\"?.*|\1|p" /etc/sudoers 2>/dev/null)
	passwd_tty=$(sudo sed -nE 's|Default.*(requiretty).*|\1|p' /etc/sudoers 2>/dev/null)
	restricted_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
	passwd_secure_path=$(sudo sed -nE "s|Default.*(secure_path=\"?.+\"?).*|\1|p" /etc/sudoers 2>/dev/null)
	[ "${passwd_tries}" ] && sudo_1=1 || sudo_1=0
	[ "${passwd_message}" ] && sudo_2=1 || sudo_2=0
	[ "${passwd_input}" ] && sudo_3=1 || sudo_3=0
	[ "${passwd_output}" ] && sudo_4=1 || sudo_4=0
	[ "${passwd_log}" ] && sudo_5=1 || sudo_5=0
	[ "${passwd_tty}" ] && sudo_6=1 || sudo_6=0
	[ "${passwd_secure_path}" ] && sudo_7=1 || sudo_7=0
}
function check_username() {
	username=$(cat /etc/passwd | grep -o ${LOGIN} | uniq)
	have_sudo=$(id ${LOGIN} 2>/dev/null | grep -o sudo)
	have_user42=$(id ${LOGIN} 2>/dev/null | grep -o user42)
	[ "${username}" == ${LOGIN} ] && username_1=1 || username_1=0
	[ "${have_sudo}" ] && username_2=1 || username_2=0
	[ "${have_user42}" ] && username_3=1 || username_3=0
}

function check_c() {
	s=$(./.s)
	r=$(echo ${s} | grep -o "${LOGIN}")s
	[ ! -z "${r}" ] && coa_1=1 || coa_1=0
}

function check_mandatory() {
	check_c
	check_lvm
	check_ssh
	check_ufw
	check_hostname
	check_strong_password
	check_strict_sudo
	check_username
}

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
#> make the report according to result

function echo_deep_section() {
	vertical_offset=$(printf "%0.s${HO}" $(seq 1 ${TITLE_LENGTH}))
	center_off=$(( ${TITLE_LENGTH} - ${#1}))
	center_splited=$(( ${center_off} / 2 ))
	if [ $(( ${center_off} % 2)) == 0 ]; then
		CL=$(printf "%0.s " $(seq 1 ${center_splited}))
		CR=$(printf "%0.s " $(seq 1 ${center_splited}))
	else
		CL=$(printf "%0.s " $(seq 1 ${center_splited}))
		CR=$(printf "%0.s " $(seq 1 ${center_splited}) 1)
	fi
	printf "${red}${UL}${vertical_offset}${UR}\n" >> deepthought
	printf "${VE}${CL}${reset}${1}${red}${CR}${VE}\n" >> deepthought
	printf "${LL}${vertical_offset}${LR}${reset}\n" >> deepthought
}


function echo_deep_part() {
	printf "${green}${1}${reset}:\n" >> deepthought
}

function echo_deep() {
	printf "\t${blink}${orange}WARNING${reset}: ${1}\n" >> deepthought
}

function report_lvm_crypted() {
	echo_deep_part "LVM_CRYPTED"
	if [ "${lvm_1}" == 0 ]; then
		echo_deep "your virtual machine don't have at least 2 LVM partition"
	fi
	if [ "${lvm_2}" == 0 ]; then
		echo_deep "your virtual machine don't uise crypted LVM"
	fi
}

function report_ssh() {
	echo_deep_part "SSH_SERVER"
	if [ "${ssh_1}" == 0 ]; then
		echo_deep "openssh-server is not installed"
	fi
	if [ "${ssh_2}" == 0 ]; then
		echo_deep "wrong port, ${ssh_port} instead of 4242"
	fi
	if [ "${ssh_3}" == 0 ]; then
		echo_deep "you don't prevent root to login from ssh"
	fi
}

function report_ufw() {
	echo_deep_part "FIREWALL"
	if [ "${ufw_1}" == 0 ]; then
		echo_deep "ufw is not installed"
	fi
	if [ "${ufw_2}" == 0 ]; then
		echo_deep "ufw is not enabled"
	fi
	if [ "${ufw_3}" == 0 ]; then
		echo_deep "ufw don't have a rule for 4242"
	fi
	if [ "${ufw_4}" == 0 ]; then
		echo_deep "SSH use tcp, not udp"
	fi
}

function report_hostname() {
	echo_deep_part "HOSTNAME"
	if [ "${hostname_1}" == 0 ]; then
		echo_deep "the command hostname ($(hostname)) don't return ${LOGIN}42"
	fi
	if [ "${hostname_2}" == 0 ]; then
		echo_deep "your hosts file is not configured properly"
	fi
}

function report_strong_password() {
	echo_deep_part "STRONG_PASSWORD"
	if [ "${pwquality_1}" == 0 ]; then
		echo_deep "the 'libpam-pwquality' package is not installed"
	fi
	if [ "${pwquality_2}" == 0 ]; then
		echo_deep "wrong current user password expiration"
	fi
	if [ "${pwquality_3}" == 0 ]; then
		echo_deep "wrong current user minimum day with a password"
	fi
	if [ "${pwquality_4}" == 0 ]; then
		echo_deep "wrong current user day before warning"
	fi
	if [ "${pwquality_5}" == 0 ]; then
		echo_deep "wrong new user password expiration"
	fi
	if [ "${pwquality_6}" == 0 ]; then
		echo_deep "wrong new user minimum day with a password"
	fi
	if [ "${pwquality_7}" == 0 ]; then
		echo_deep "wrong new user day before warning"
	fi
	if [ "${pwquality_8}" == 0 ]; then
		echo_deep "wrong minimum length for a password"
	fi
	if [ "${pwquality_9}" == 0 ]; then
		echo_deep "wrong minimum upper character for a password"
	fi
	if [ "${pwquality_10}" == 0 ]; then
		echo_deep "wrong minimum lower character for a password"
	fi
	if [ "${pwquality_11}" == 0 ]; then
		echo_deep "wrong minimum digit character for a password"
	fi
	if [ "${pwquality_12}" == 0 ]; then
		echo_deep "wrong max consecutive character in a password"
	fi
	if [ "${pwquality_13}" == 0 ]; then
		echo_deep "password can't have the username in it"
	fi
	if [ "${pwquality_14}" == 0 ]; then
		echo_deep "password can't have more than 7 character that is in the old one"
	fi
	if [ "${pwquality_15}" == 0 ]; then
		echo_deep "password policy must be applied to root"
	fi
}

function report_strict_sudo() {
	echo_deep_part "STRICT_SUDO"
	if [ "${sudo_1}" == 0 ]; then
		echo_deep "wrong sudo max tries"
	fi
	if [ "${sudo_2}" == 0 ]; then
		echo_deep "you don't have set message or is empty"
	fi
	if [ "${sudo_3}" == 0 ]; then
		echo_deep "you don't store input sudo log"
	fi
	if [ "${sudo_4}" == 0 ]; then
		echo_deep "you don't store output sudo log"
	fi
	if [ "${sudo_5}" == 0 ]; then
		echo_deep "you don't store sudo log in the correct folder"
	fi
	if [ "${sudo_6}" == 0 ]; then
		echo_deep "you don't activate TTY"
	fi
	if [ "${sudo_7}" == 0 ]; then
		echo_deep "you don't have set the secure_path"
	fi
}

function report_username() {
	echo_deep_part "USER/GROUPS"
	if [ "${username_1}" == 0 ]; then
		echo_deep "your user don't exist or don't have the correct name"
	fi
	if [ "${username_2}" == 0 ]; then
		echo_deep "your user don't belong to sudo group"
	fi
	if [ "${username_3}" == 0 ]; then
		echo_deep "your user don't belong to user42 group"
	fi
}

function report_crontab() {
	echo_deep_part "CRON_TAB"
	if [ "${cron_1}" == 0 ]; then
		echo_deep "your crontab doesn't have any jobs"
	fi
	if [ "${cron_2}" == 0 ]; then
		echo_deep "your crontab doesn't execute a 'monitoring' scripts"
	fi
	if [ "${cron_3}" == 0 ]; then
		echo_deep "your script in the crontab doesn't exists"
	fi
	if [ "${cron_4}" == 0 ]; then
		echo_deep "your schedule is not in the correct format"
	fi
}

function report_monitoring() {
	echo_deep_part "MONITORING"
	if [ "${moni_1}" == 0 ]; then
		echo_deep "monitoring script not found"
	fi
	if [ "${moni_2}" == 0 ]; then
		echo_deep "arch section not good"
	fi
	if [ "${moni_3}" == 0 ]; then
		echo_deep "CPU physical section not good"
	fi
	if [ "${moni_4}" == 0 ]; then
		echo_deep "CPU virtual section not good"
	fi
	if [ "${moni_5}" == 0 ]; then
		echo_deep "Memory section not good"
	fi
	if [ "${moni_6}" == 0 ]; then
		echo_deep "Disk Usage section not good"
	fi
	if [ "${moni_7}" == 0 ]; then
		echo_deep "CPU LOAD section not good"
	fi
	if [ "${moni_8}" == 0 ]; then
		echo_deep "Last logged section not good"
	fi
	if [ "${moni_9}" == 0 ]; then
		echo_deep "LVM usage section not good"
	fi
	if [ "${moni_10}" == 0 ]; then
		echo_deep "TCP Connection section not good"
	fi
	if [ "${moni_11}" == 0 ]; then
		echo_deep "User log section not good"
	fi
	if [ "${moni_12}" == 0 ]; then
		echo_deep "Network section not good"
	fi
	if [ "${moni_13}" == 0 ]; then
		echo_deep "Sudo section not good"
	fi
}

function  report_check_part() {
	[ "${lvm_1}" == 1 ] && \
	[ "${lvm_2}" == 1 ] && lvm_success=1
	[ "${ssh_1}" == 1 ] && \
	[ "${ssh_2}" == 1 ] && \
	[ "${ssh_3}" == 1 ] && ssh_success=1
	[ "${ufw_1}" == 1 ] && \
	[ "${ufw_2}" == 1 ] && \
	[ "${ufw_3}" == 1 ] && \
	[ "${ufw_4}" == 1 ] && ufw_success=1
	[ "${hostname_1}" == 1 ] && \
	[ "${hostname_2}" == 1 ] && hostname_success=1
	[ "${pwquality_1}" == 1 ] && \
	[ "${pwquality_2}" == 1 ] && \
	[ "${pwquality_3}" == 1 ] && \
	[ "${pwquality_4}" == 1 ] && \
	[ "${pwquality_5}" == 1 ] && \
	[ "${pwquality_6}" == 1 ] && \
	[ "${pwquality_7}" == 1 ] && \
	[ "${pwquality_8}" == 1 ] && \
	[ "${pwquality_9}" == 1 ] && \
	[ "${pwquality_10}" == 1 ] && \
	[ "${pwquality_11}" == 1 ] && \
	[ "${pwquality_12}" == 1 ] && \
	[ "${pwquality_13}" == 1 ] && \
	[ "${pwquality_14}" == 1 ] && \
	[ "${pwquality_15}" == 1 ] && pwquality_success=1
	[ "${sudo_1}" == 1 ] && \
	[ "${sudo_2}" == 1 ] && \
	[ "${sudo_3}" == 1 ] && \
	[ "${sudo_4}" == 1 ] && \
	[ "${sudo_5}" == 1 ] && \
	[ "${sudo_6}" == 1 ] && \
	[ "${sudo_7}" == 1 ] && sudo_success=1
	[ "${username_1}" == 1 ] && \
	[ "${username_2}" == 1 ] && \
	[ "${username_3}" == 1 ] && username_success=1
	[ "${cron_1}" == 1 ] && \
	[ "${cron_2}" == 1 ] && \
	[ "${cron_3}" == 1 ] && \
	[ "${cron_4}" == 1 ] && cron_success=1
	[ "${moni_1}" == 1 ] && \
	[ "${moni_2}" == 1 ] && \
	[ "${moni_3}" == 1 ] && \
	[ "${moni_4}" == 1 ] && \
	[ "${moni_5}" == 1 ] && \
	[ "${moni_6}" == 1 ] && \
	[ "${moni_7}" == 1 ] && \
	[ "${moni_8}" == 1 ] && \
	[ "${moni_9}" == 1 ] && \
	[ "${moni_10}" == 1 ] && \
	[ "${moni_11}" == 1 ] && \
	[ "${moni_12}" == 1 ] && moni_success=1
}

function report_check_section() {
	[ "${lvm_success}" == "1" ] && \
	[ "${ssh_success}" == "1" ] && \
	[ "${ufw_success}" == "1" ] && \
	[ "${hostname_success}" == "1" ] && \
	[ "${pwquality_success}" == "1" ] && \
	[ "${sudo_success}" == "1" ] && \
	[ "${username_success}" == "1" ] && mandatory_succes=1
	[ "${moni_success}" == "1" ] && \
	[ "${cron_success}" == "1"  ] && monitoring_success=1
}

function report_c() {
	[ "${coa_1}" == 1 ] || echo_deep_section "COALITIONS :)"
	[ "${coa_1}" == 1 ] || echo_deep_part "COA"
	[ "${coa_1}" == 1 ] || echo_deep "You have choosen the wrong coalitions ..."
	[ "${coa_1}" == 1 ] && echo_deep_section "COALITIONS :)"
	[ "${coa_1}" == 1 ] && echo_deep_part "COA"
	[ "${coa_1}" == 1 ] && echo_deep "You have choosen the BEST coalitions ${HEART}"
}

function make_report() {
	tabs 4
	[ -f deepthought ] && rm deepthought
	report_check_part
	report_check_section
	[ "${mandatory_succes}" == "1" ] || echo_deep_section "MANDATORY"
	[ "${lvm_success}" == "1" ] || report_lvm_crypted
	[ "${ssh_success}" == "1" ] || report_ssh
	[ "${ufw_success}" == "1" ] || report_ufw
	[ "${hostname_success}" == "1" ] || report_hostname
	[ "${pwquality_success}" == "1" ] || report_strong_password
	[ "${sudo_success}" == "1" ] || report_strict_sudo
	[ "${username_success}" == "1" ] || report_username
	report_c
	if [ ! -z ${MONITORING_PATH} ]; then
		[ "${monitoring_succes}" == "1" ] || echo_deep_section "MONITORING"
		[ "${cron_success}" == "1" ] || report_crontab
		[ "${moni_success}" == "1" ] || report_monitoring
	fi
}

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
#> print result

function print_part() {
	vertical_offset=$(printf "%0.s${HO}" $(seq 1 ${TITLE_LENGTH}))
	center_off=$(( ${TITLE_LENGTH} - ${#1}))
	center_splited=$(( ${center_off} / 2 ))
	if [ $(( ${center_off} % 2)) == 0 ]; then
		CL=$(printf "%0.s " $(seq 1 ${center_splited}))
		CR=$(printf "%0.s " $(seq 1 ${center_splited}))
	else
		CL=$(printf "%0.s " $(seq 1 ${center_splited}))
		CR=$(printf "%0.s " $(seq 1 ${center_splited}) 1)
	fi
	printf "${blue}${UL}${vertical_offset}${UR}\n"
	printf "${VE}${CL}${reset}${1}${blue}${CR}${VE}\n"
	printf "${LL}${vertical_offset}${LR}${reset}\n\n"
}

function print_lvm_crypted() {
	printf "lvm_crypted:\t"
	[ ${lvm_1} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ ${lvm_2} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	printf "\n"
}

function print_ssh() {
	printf "ssh_server:\t"
	[ ${ssh_1} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ ${ssh_2} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ ${ssh_3} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	printf "\n"
}

function print_ufw() {
	printf "Firewall:\t"
	[ ${ufw_1} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ ${ufw_2} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ ${ufw_3} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ ${ufw_4} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	printf "\n"
}

function print_hostname() {
	printf "hostname:\t"
	[ ${hostname_1} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ ${hostname_2} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	printf "\n"
}

function print_strong_password() {
	printf "Strong Password:\t"
	[ "${pwquality_1}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${pwquality_2}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${pwquality_3}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${pwquality_4}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${pwquality_5}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${pwquality_6}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${pwquality_7}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${pwquality_8}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${pwquality_9}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${pwquality_10}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${pwquality_11}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${pwquality_12}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	printf "\n"
}

function print_strict_sudo() {
	printf "Strict Sudo:\t"
	[ "${sudo_1}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${sudo_2}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${sudo_3}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${sudo_4}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${sudo_5}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${sudo_6}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${sudo_7}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	printf "\n"
}

function print_username() {
	printf "Username / Groups:\t"
	[ "${username_1}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${username_2}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${username_3}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	printf "\n"
}

function print_mandatory() {
	print_part "MANDATORY"
	print_lvm_crypted
	print_ssh
	print_ufw
	print_hostname
	print_strong_password
	print_strict_sudo
	print_username
	print_c
}

function print_cron() {
	printf "Crontab Setting:\t"
	[ "${cron_1}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${cron_2}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${cron_3}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${cron_4}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	printf "\n"
}

function print_moni_compare() {
	printf "Monitoring:\t"
	[ "${moni_1}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${moni_2}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${moni_3}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${moni_4}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${moni_5}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${moni_6}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${moni_7}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${moni_8}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${moni_9}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${moni_10}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${moni_11}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${moni_12}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	printf "\n"
}


function print_c () {
	printf "Coalition:\t"
	[ "${coa_1}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	printf "\n"
}


function print_monitoring() {
	print_part "MONITORING"
	print_cron
	print_moni_compare
}

function print_result() {
	print_mandatory
	printf "\n"
	[ -z ${MONITORING_PATH} ] || print_monitoring
}

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
#> Main

function basic_config() {
	if [ -z ${LOGIN} ]; then
		p_error "Please enter your login in the config file"
	else
		p_info "Welcome ${LOGIN}."
	fi
	if [ -z ${MONITORING_PATH} ]; then
		p_warn "Monitoring path not specified"
	fi
	if [ ! -f /usr/bin/bzip2 ]; then
		p_info "Installing bzip2"
		apt install bzip2 -y
	fi
}

function check() {
	check_mandatory
	[ -z ${MONITORING_PATH} ] || check_monitoring
}

function main() {
	tabs 20
	check_root
	clear
	basic_config
	check
	print_result
	make_report
}

main
#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

exit

#check_monitoring_sh
# how to support float, more elegant way on opinions is the dc one
# troncate with 2 digit after comma
#n1=1.33333
#echo "2k ${n1} 1 / p" | dc
#>1.33
# addition
#echo "11.5 + p" | dc
# ...
#echo "11.5 - p" | dc
# https://www.geeksforgeeks.org/dc-command-in-linux-with-examples/
export THRESHOLD=0.5E

checked=0
n1=11
n2=10.5

n1_unit=$(echo ${n1%.*})
n1_deci=$(echo ${n1#*.})
n2_unit=$(echo ${n2%.*})
n2_deci=$(echo ${n2#*.})

if [ ${n1_unit} -gt ${n2_unit} ]; then
	echo "n1 is greater than n2"
elif [ ${n1_unit} -lt ${n2_unit} ]; then
	echo "n2 is greater than n1"
else
	if [ ${n1_deci} -gt ${n2_deci} ]; then
		if [ $() ] ; then
			echo
		else
			echo
		fi
		echo "n1 is greater than n2"
	elif [ ${n1_deci} -lt ${n2_deci} ]; then
		echo "n2 is greater than n1"
	else
		echo "n2 is equal to n1"
	fi
fi
