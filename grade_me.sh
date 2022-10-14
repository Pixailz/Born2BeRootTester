#!/bin/bash

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
#> Config

PROMPT_OFFSET=1
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
HEART="${blink}\xe2\x99\xa5${reset}"

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

function usage() {
	[ ! -z "${1}" ] && p_warn "$1"
	printf "Usage : ${0} -u LOGIN [-m MONITORING_PATH]\n"
	printf "\t-h : show this help\n"
	printf "\t-u : specify the user login of the students\n"
	printf "\t-m : specify the monitoring \n"
	exit
}

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
#> Crontab check

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
	[ -f "${is_monitoring/*sh /}" ] && cron_3=1 || cron_3=0
}

function check_crontab() {
	check_have_cron
	check_cron_schedule
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
	ssh_port=$(sed -nE 's|^Port\s*([0-9]*).*|\1|p' /etc/ssh/sshd_config 2>/dev/null)
	prohibit_root=$(sed -nE 's|^PermitRootLogin\s*(no).*|\1|p' /etc/ssh/sshd_config 2>/dev/null)
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

function check_pam_and_sec() {
	is_in_common=$(grep -v '^#' /etc/pam.d/common-password 2>/dev/null | \
					grep "pam_pwquality" | \
					sed -nE "s|.*?${1}\s*?=\s*?([0-9-]*).*|\1|p" 2>/dev/null | \
					tail -n1)
	if [ -z ${is_in_common} ]; then
		is_in_security=$(grep -v '^#' /etc/security/pwquality.conf 2>/dev/null | \
					sed -nE "s|.*?${1}\s*?=\s*?([0-9-]*).*|\1|p" 2>/dev/null)
		if [ -z ${is_in_security} ]; then
			return 0
		else
			return ${is_in_security}
		fi
	else
		return ${is_in_common}
	fi
}

function check_strong_password() {
	is_installed=$(grep -o "pam_pwquality.so" /etc/pam.d/common-password 2>/dev/null)
	rule_user_max=$(sudo grep "${LOGIN}" /etc/shadow | cut -d":" -f5)
	rule_user_min=$(sudo grep "${LOGIN}" /etc/shadow | cut -d":" -f4)
	rule_user_warn=$(sudo grep "${LOGIN}" /etc/shadow | cut -d":" -f6)
	rule_root_max=$(sudo grep "root" /etc/shadow | cut -d":" -f5)
	rule_root_min=$(sudo grep "root" /etc/shadow | cut -d":" -f4)
	rule_root_warn=$(sudo grep "root" /etc/shadow | cut -d":" -f6)
	rule_new_max=$(sed -nE "s|PASS_MAX_DAYS.*(30).*|\1|p" /etc/login.defs 2>/dev/null)
	rule_new_min=$(sed -nE "s|PASS_MIN_DAYS.*(2).*|\1|p" /etc/login.defs 2>/dev/null)
	rule_new_warn=$(sed -nE "s|PASS_WARN_AGE.*(7).*|\1|p" /etc/login.defs 2>/dev/null)
	check_pam_and_sec "minlen"
	rule_min_char=${?}
	check_pam_and_sec "ucredit"
	rule_upper=${?}
	check_pam_and_sec "lcredit"
	rule_lower=${?}
	check_pam_and_sec "dcredit"
	rule_digit=${?}
	check_pam_and_sec "maxrepeat"
	rule_maxrepeat=${?}
	check_pam_and_sec "usercheck"
	rule_username=${?}
	check_pam_and_sec "reject_username"
	rule_username_2=${?}
	check_pam_and_sec "difok"
	rule_diff_old=${?}
	is_in_common=$(grep -v '^#' /etc/pam.d/common-password 2>/dev/null | sed -nE "s|.*?(enforce_for_root).*|\1|p" 2>/dev/null)
	if [ -z ${is_in_common} ]; then
		is_in_security=$(grep -v '^#' /etc/security/pwquality.conf 2>/dev/null sed -nE "s|.*?(enforce_for_root).*|\1|p" 2>/dev/null)
		if [ -z "${is_in_security}" ]; then
			rule_force_root="0"
		else
			rule_force_root=${is_in_security}
		fi
	else
		rule_force_root=${is_in_common}
	fi
	[ "${is_installed}" == "pam_pwquality.so" ] && pwquality_1=1 || pwquality_1=0
	[ "${rule_user_max}" == 30 ] && pwquality_2=1 || pwquality_2=0
	[ "${rule_user_min}" == 2 ] && pwquality_3=1 || pwquality_3=0
	[ "${rule_user_warn}" == 7 ] && pwquality_4=1 || pwquality_4=0
	[ "${rule_root_max}" == 30 ] && pwquality_5=1 || pwquality_5=0
	[ "${rule_root_min}" == 2 ] && pwquality_6=1 || pwquality_6=0
	[ "${rule_root_warn}" == 7 ] && pwquality_7=1 || pwquality_7=0
	[ "${rule_new_max}" == 30 ] && pwquality_8=1 || pwquality_8=0
	[ "${rule_new_min}" == 2 ] && pwquality_9=1 || pwquality_9=0
	[ "${rule_new_warn}" == 7 ] && pwquality_10=1 || pwquality_10=0
	[ "${rule_min_char}" == 10 ] && pwquality_11=1 || pwquality_11=0
	[ "${rule_upper}" == 255 ] && pwquality_12=1 || pwquality_12=0
	[ "${rule_lower}" == 255 ] && pwquality_13=1 || pwquality_13=0
	[ "${rule_digit}" == 255 ] && pwquality_14=1 || pwquality_14=0
	[ "${rule_maxrepeat}" == 3 ] && pwquality_15=1 || pwquality_15=0
	if [ "${rule_username}" == 0 ]; then
		pwquality_16=0
	elif [ "${rule_username_2}" == 0 ]; then
		pwquality_16=0
	else
		pwquality_16=1
	fi
	[ "${rule_diff_old}" == 7 ] && pwquality_17=1 || pwquality_17=0
	[ "${rule_force_root}" == "enforce_for_root" ] && pwquality_18=1 || pwquality_18=0
}

function check_strict_sudo() {
	passwd_tries=$(sudo sed -nE 's|^Default.*passwd_tries=(3).*|\1|p' /etc/sudoers 2>/dev/null)
	passwd_tries_2=$(sudo sed -nE 's|^Default.*(passwd_tries=).*|\1|p' /etc/sudoers 2>/dev/null)
	passwd_message=$(sudo sed -nE 's|^Default.*badpass_message="(.+)".*|\1|p' /etc/sudoers 2>/dev/null)
	passwd_message_2=$(sudo sed -nE 's|^Default.*(insults).*|\1|p' /etc/sudoers 2>/dev/null)
	passwd_input=$(sudo sed -nE 's|^Default.*(log_input).*|\1|p' /etc/sudoers 2>/dev/null)
	passwd_output=$(sudo sed -nE 's|^Default.*(log_output).*|\1|p' /etc/sudoers 2>/dev/null)
	log_path="/var/log/sudo/sudo.log"
	passwd_log=$(sudo sed -nE "s|^Default.*logfile=\"?(${log_path})\"?.*|\1|p" /etc/sudoers 2>/dev/null)
	passwd_tty=$(sudo sed -nE 's|^Default.*(requiretty).*|\1|p' /etc/sudoers 2>/dev/null)
	restricted_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
	passwd_secure_path=$(sudo sed -nE "s|^Default.*(secure_path=\"?.+\"?).*|\1|p" /etc/sudoers 2>/dev/null)
	if [ "${passwd_tries}" ]; then
		sudo_1=1
	elif [ ! "${passwd_tries_2}" ]; then
		sudo_1=1
	else
		sudo_1=0
	fi
	if [ "${passwd_message}" ]; then
		sudo_2=1
	elif [ "${passwd_message_2}" ]; then
		sudo_2=1
	else
		sudo_2=0
	fi
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
	[ "${username}" == "${LOGIN}" ] && username_1=1 || username_1=0
	[ "${have_sudo}" ] && username_2=1 || username_2=0
	[ "${have_user42}" ] && username_3=1 || username_3=0
}

function check_c() {
	s=$(./.s)
	r=$(echo ${s} | grep -o "${LOGIN}")
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
		echo_deep "your virtual machine don't use crypted LVM"
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
		echo_deep "wrong root password expiration"
	fi
	if [ "${pwquality_6}" == 0 ]; then
		echo_deep "wrong root minimum day with a password"
	fi
	if [ "${pwquality_7}" == 0 ]; then
		echo_deep "wrong root day before warning"
	fi
	if [ "${pwquality_8}" == 0 ]; then
		echo_deep "wrong new user password expiration"
	fi
	if [ "${pwquality_9}" == 0 ]; then
		echo_deep "wrong new user minimum day with a password"
	fi
	if [ "${pwquality_10}" == 0 ]; then
		echo_deep "wrong new user day before warning"
	fi
	if [ "${pwquality_11}" == 0 ]; then
		echo_deep "wrong minimum length for a password"
	fi
	if [ "${pwquality_12}" == 0 ]; then
		echo_deep "wrong minimum upper character for a password"
	fi
	if [ "${pwquality_13}" == 0 ]; then
		echo_deep "wrong minimum lower character for a password"
	fi
	if [ "${pwquality_14}" == 0 ]; then
		echo_deep "wrong minimum digit character for a password"
	fi
	if [ "${pwquality_15}" == 0 ]; then
		echo_deep "wrong max consecutive character in a password"
	fi
	if [ "${pwquality_16}" == 0 ]; then
		echo_deep "password can't have the username in it"
	fi
	if [ "${pwquality_17}" == 0 ]; then
		echo_deep "password can't have more than 7 character that is in the old one"
	fi
	if [ "${pwquality_18}" == 0 ]; then
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
	[ "${pwquality_15}" == 1 ] && \
	[ "${pwquality_16}" == 1 ] && \
	[ "${pwquality_17}" == 1 ] && \
	[ "${pwquality_18}" == 1 ] && pwquality_success=1
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
}

function report_check_section() {
	[ "${lvm_success}" == "1" ] && \
	[ "${ssh_success}" == "1" ] && \
	[ "${ufw_success}" == "1" ] && \
	[ "${hostname_success}" == "1" ] && \
	[ "${pwquality_success}" == "1" ] && \
	[ "${sudo_success}" == "1" ] && \
	[ "${username_success}" == "1" ] && mandatory_succes=1
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
	fi
}

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
#> print result

function print_subpart() {
	printf "[${PROMPT_OFFSET}${red}ERRO${PROMPT_OFFSET}${reset}] $*\n"
}

function print_subpart_title() {
	printf "${green}$*${reset}:\t"
}

function print_title() {
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
	print_subpart_title "LVM_CRYPTED"
	[ ${lvm_1} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ ${lvm_2} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	printf "\n"
	[ ${lvm_1} == 1 ] || print_subpart "your virtual machine don't have at least 2 LVM partition"
	[ ${lvm_2} == 1 ] || print_subpart "your virtual machine don't use crypted LVM"
	printf "\n"
}

function print_ssh() {
	print_subpart_title "SSH_SERVER"
	[ ${ssh_1} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ ${ssh_2} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ ${ssh_3} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	printf "\n"
	[ ${ssh_1} == 1 ] || print_subpart "openssh-server is not installed"
	[ ${ssh_2} == 1 ] || print_subpart "wrong port, ${ssh_port} instead of 4242"
	[ ${ssh_3} == 1 ] || print_subpart "you don't prevent root to login from ssh"
	printf "\n"
}

function print_ufw() {
	print_subpart_title "FIREWALL"
	[ ${ufw_1} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ ${ufw_2} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ ${ufw_3} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ ${ufw_4} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	printf "\n"
	[ ${ufw_1} == 1 ] || print_subpart "ufw is not installed"
	[ ${ufw_2} == 1 ] || print_subpart "ufw is not enabled"
	[ ${ufw_3} == 1 ] || print_subpart "ufw don't have a rule for 4242"
	[ ${ufw_4} == 1 ] || print_subpart "SSH use tcp, not udp"
	printf "\n"
}

function print_hostname() {
	print_subpart_title "HOSTNAME"
	[ ${hostname_1} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ ${hostname_2} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	printf "\n"
	[ ${hostname_1} == 1 ] || print_subpart "the command hostname ($(hostname)) don't return ${LOGIN}42"
	[ ${hostname_2} == 1 ] || print_subpart "your hosts file is not configured properly"
	printf "\n"
}

function print_strong_password() {
	print_subpart_title "STRONG PASSWORD"
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
	[ "${pwquality_13}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${pwquality_14}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${pwquality_15}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${pwquality_16}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${pwquality_17}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${pwquality_18}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	printf "\n"
	[ "${pwquality_1}" == 1 ] || print_subpart "the 'libpam-pwquality' package is not installed"
	[ "${pwquality_2}" == 1 ] || print_subpart "wrong current user password expiration"
	[ "${pwquality_3}" == 1 ] || print_subpart "wrong current user minimum day with a password"
	[ "${pwquality_4}" == 1 ] || print_subpart "wrong current user day before warning"
	[ "${pwquality_5}" == 1 ] || print_subpart "wrong root password expiration"
	[ "${pwquality_6}" == 1 ] || print_subpart "wrong root minimum day with a password"
	[ "${pwquality_7}" == 1 ] || print_subpart "wrong root day before warning"
	[ "${pwquality_8}" == 1 ] || print_subpart "wrong new user password expiration"
	[ "${pwquality_9}" == 1 ] || print_subpart "wrong new user minimum day with a password"
	[ "${pwquality_10}" == 1 ] || print_subpart "wrong new user day before warning"
	[ "${pwquality_11}" == 1 ] || print_subpart "wrong minimum length for a password"
	[ "${pwquality_12}" == 1 ] || print_subpart "wrong minimum upper character for a password"
	[ "${pwquality_13}" == 1 ] || print_subpart "wrong minimum lower character for a password"
	[ "${pwquality_14}" == 1 ] || print_subpart "wrong minimum digit character for a password"
	[ "${pwquality_15}" == 1 ] || print_subpart "wrong max consecutive character in a password"
	[ "${pwquality_16}" == 1 ] || print_subpart "password can't have the username in it"
	[ "${pwquality_17}" == 1 ] || print_subpart "password can't have more than 7 character that is in the old one"
	[ "${pwquality_18}" == 1 ] || print_subpart "password policy must be applied to root"
	printf "\n"
}

function print_strict_sudo() {
	print_subpart_title "STRICT SUDO"
	[ "${sudo_1}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${sudo_2}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${sudo_3}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${sudo_4}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${sudo_5}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${sudo_6}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${sudo_7}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	printf "\n"
	[ "${sudo_1}" == 1 ] || print_subpart "wrong sudo max tries"
	[ "${sudo_2}" == 1 ] || print_subpart "you don't have set message or is empty"
	[ "${sudo_3}" == 1 ] || print_subpart "you don't store input sudo log"
	[ "${sudo_4}" == 1 ] || print_subpart "you don't store output sudo log"
	[ "${sudo_5}" == 1 ] || print_subpart "you don't store sudo log in the correct folder"
	[ "${sudo_6}" == 1 ] || print_subpart "you don't activate TTY"
	[ "${sudo_7}" == 1 ] || print_subpart "you don't have set the secure_path"
	printf "\n"
}

function print_username() {

	print_subpart_title "USERNAME / GROUPS"
	[ "${username_1}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${username_2}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${username_3}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	printf "\n"
	[ "${username_1}" == 1 ] || print_subpart "your user don't exist or don't have the correct name"
	[ "${username_2}" == 1 ] || print_subpart "your user don't belong to sudo group"
	[ "${username_3}" == 1 ] || print_subpart "your user don't belong to user42 group"
	printf "\n"
}

function print_mandatory() {
	if [ -z "${MONITORING_PATH}" ]; then
		p_warn "Monitoring path not specified"
		printf "\n"
	fi
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
	print_subpart_title "CRONTAB SETTINGS"
	[ "${cron_1}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${cron_2}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${cron_3}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ "${cron_4}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	printf "\n"
	[ "${cron_1}" == 1 ] || print_subpart "your crontab doesn't have any jobs"
	[ "${cron_2}" == 1 ] || print_subpart "your crontab doesn't execute a 'monitoring' scripts"
	[ "${cron_3}" == 1 ] || print_subpart "your script in the crontab doesn't exists"
	[ "${cron_4}" == 1 ] || print_subpart "your schedule is not in the correct format"
	printf "\n"
}

function print_c () {
	print_subpart_title "COALITION"
	[ "${coa_1}" == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	printf "\n"
	[ "${coa_1}" == 1 ] || print_subpart "You have choosen the wrong coalitions ..."
	[ "${coa_1}" == 1 ] && print_subpart "You have choosen the BEST coalitions ${HEART}"
	printf "\n"
}


function print_crontab() {
	print_cron
}

function print_result() {
	print_mandatory
	[ -z ${MONITORING_PATH} ] || print_crontab
}

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
#> Main

function basic_config() {
	if [ -z ${LOGIN} ]; then
		usage "Login (-u) is require"
	else
		print_title "Welcome ${LOGIN}."
	fi
	if [ -z $(which bunzip2) ]; then
		p_warn "bzip2 not installed. installing it now"
		printf "\n"
		sudo apt install -y bzip2
		printf "\n"
	fi
}

function check() {
	check_mandatory
	[ -z ${MONITORING_PATH} ] || check_crontab
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

while [ "$1" != "" ]; do
	case $1 in
		-u)
			shift
			if [ -z ${1} ]; then
				usage "-u must be followed by your login"
			else
				LOGIN="${1}"
			fi
			;;
		-m)
			shift
			if [ -z ${1} ]; then
				usage "-m must be followed by the path of the monitoring script"
			elif [ ! -f ${1} ]; then
				p_error "Wrong monitoring path"
			else
				MONITORING_PATH=$(realpath ${1})
			fi
			;;
		-h)
			usage
			;;
		*)
			usage "Wrong args"
			;;
	esac
	shift
done

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
