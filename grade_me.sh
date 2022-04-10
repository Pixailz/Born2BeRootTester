#!/bin/bash

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
#> Config

LOGIN=brda-sil

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

reset="\x1b[0m"

SUCCESS="[${green}+${reset}] "
FAILED="[${red}-${reset}] "

UL="\xe2\x95\x94"
HO="\xe2\x95\x90"
UR="\xe2\x95\x97"
VE="\xe2\x95\x91"
LL="\xe2\x95\x9a"
LR="\xe2\x95\x9d"

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
#> Utils

function check_root() {
	if [ ${EUID} != 0 ]; then
		p_error "Please run as root."
	fi
}

function p_error() {
	printf "[${PROMPT_OFFSET}${red}ERROR${PROMPT_OFFSET}${reset}] $*\n"
	exit
}

function p_info() {
	printf "[${PROMPT_OFFSET}${blue}INFO${PROMPT_OFFSET}${reset}] $*\n"
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
	is_installed=$(sudo systemctl list-units | grep -o ssh)
	ssh_port=$(sed -nE 's|^Port\s*(4242)$|\1|p' /etc/ssh/sshd_config)
	prohibit_root=$(sed -nE 's|^PermitRootLogin\s*(no)$|\1|p' /etc/ssh/sshd_config)
	[ ${is_installed} ] && ssh_1=1 || ssh_1=0
	[ ${ssh_port} ] && ssh_2=1 || ssh_2=0
	[ ${prohibit_root} ] && ssh_3=1 || ssh_3=0
}

function check_ufw() {
	is_installed=$(sudo which ufw)
	is_enabled=$(sudo ufw status | sed -nE 's|Status: (active)|\1|p')
	v4_rule=$(sudo ufw status | sed -nE 's|^4242/tcp\s*(ALLOW)|\1|p')
	v6_rule=$(sudo ufw status | sed -nE 's|^4242/tcp \(v6\)\s*(ALLOW).*|\1|p')
	[ ${is_installed} ] && ufw_1=1 || ufw_1=0
	[ ${is_enabled} ] && ufw_2=1 || ufw_2=0
	if [ ! "${v4_rule}" != "ALLOW" ] || [ ! "${v6_rule}" != "ALLOW" ]; then
		ufw_3=1
	else
		ufw_3=0
	fi
}

function check_hostname() {
	hostname="${LOGIN}42"
	hosts=$(sed -nE 's|127.0.0.1\t([a-z0-9\-]{1,63})|\1|p' /etc/hosts)
	[ ${hostname} == $(hostname) ] && hostname_1=1 || hostname_1=0
	if [ ${hosts} == "localhost" ]; then
		hosts2=$(sed -nE 's|127.0.1.1\t([a-z0-9\-]{1,63})|\1|p' /etc/hosts)
		[ ${hosts2} == ${hostname} ] && hostname_2=1 || hostname_2=0
	else
		[ ${hosts} == ${hostname} ] && hostname_2=1 || hostname_2=0
	fi
}

function check_strong_password() {
	is_installed=$(grep -o "pam_pwquality.so" /etc/pam.d/common-password)
	rule_max=$(sed -nE "s|PASS_MAX_DAYS.*(30).*|\1|p" /etc/login.defs)
	rule_min=$(sed -nE "s|PASS_MIN_DAYS.*(2).*|\1|p" /etc/login.defs)
	rule_warn=$(sed -nE "s|PASS_WARN_AGE.*(7).*|\1|p" /etc/login.defs)
	rule_min_char=$(sed -nE "s|.*minlen=(10).*|\1|p" /etc/pam.d/common-password)
	rule_upper=$(sed -nE "s|.*ucredit=(-1).*|\1|p" /etc/pam.d/common-password)
	rule_lower=$(sed -nE "s|.*lcredit=(-1).*|\1|p" /etc/pam.d/common-password)
	rule_digit=$(sed -nE "s|.*dcredit=(-1).*|\1|p" /etc/pam.d/common-password)
	rule_maxrepeat=$(sed -nE "s|.*maxrepeat=(3).*|\1|p" /etc/pam.d/common-password)
	rule_username=$(sed -nE "s|.*usercheck=([0-9]).*|\1|p" /etc/pam.d/common-password)
	rule_diff_old=$(sed -nE "s|.*difok=(7).*|\1|p" /etc/pam.d/common-password)
	rule_force_root=$(grep -o "enforce_for_root" /etc/pam.d/common-password)
	[ "${is_installed}" == "pam_pwquality.so" ] && pwquality_1=1 || pwquality_1=0
	[ "${rule_max}" ] && pwquality_2=1 || pwquality_2=0
	[ "${rule_min}" ] && pwquality_3=1 || pwquality_3=0
	[ "${rule_warn}" ] && pwquality_4=1 || pwquality_4=0
	[ "${rule_min_char}" ] && pwquality_5=1 || pwquality_5=0
	[ "${rule_upper}" ] && pwquality_6=1 || pwquality_6=0
	[ "${rule_lower}" ] && pwquality_7=1 || pwquality_7=0
	[ "${rule_digit}" ] && pwquality_8=1 || pwquality_8=0
	[ "${rule_maxrepeat}" ] && pwquality_9=1 || pwquality_9=0
	[ "${rule_username}" ] && pwquality_10=1 || pwquality_10=0
	[ "${rule_diff_old}" ] && pwquality_11=1 || pwquality_11=0
	[ "${rule_force_root}" ] && pwquality_12=1 || pwquality_12=0
}

function check_strict_sudo() {
	passwd_tries=$(sudo sed -nE 's|.*passwd_tries=(3).*|\1|p' /etc/sudoers)
	passwd_message=$(sudo sed -nE 's|.*badpass_message="(.+)".*|\1|p' /etc/sudoers)
	passwd_input=$(sudo sed -nE 's|Default.*(log_input).*|\1|p' /etc/sudoers)
	passwd_output=$(sudo sed -nE 's|Default.*(log_output).*|\1|p' /etc/sudoers)
	log_path="/var/log/sudo/sudo.log"
	passwd_log=$(sudo sed -nE "s|.*logfile=\"(${log_path})\".*|\1|p" /etc/sudoers)
	passwd_tty=$(sudo sed -nE 's|Default.*(requiretty).*|\1|p' /etc/sudoers)
	restricted_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
	passwd_secure_path=$(sudo sed -nE "s|Default.*(secure_path).*|\1|p" /etc/sudoers)
	[ "${passwd_tries}" ] && sudo_1=1 || sudo_1=0
	[ "${passwd_message}" ] && sudo_2=1 || sudo_2=0
	[ "${passwd_input}" ] && sudo_3=1 || sudo_3=0
	[ "${passwd_output}" ] && sudo_4=1 || sudo_4=0
	[ "${passwd_log}" ] && sudo_5=1 || sudo_5=0
	[ "${passwd_tty}" ] && sudo_6=1 || sudo_6=0
	[ "${passwd_secure_path}" ] && sudo_7=1 || sudo_7=0
}
function check_username() {
	username=$(logname)
	have_sudo=$(id ${username} | grep -o sudo)
	have_user42=$(id ${username} | grep -o user42)
	[ ${username} == ${LOGIN} ] && username_1=1 || username_1=0
	[ "${have_sudo}" ] && username_2=1 || username_2=0
	[ "${have_user42}" ] && username_3=1 || username_3=0
}

function check_mandatory() {
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
	printf "${UL}${vertical_offset}${UR}\n"
	printf "${VE}${CL}${1}${CR}${VE}\n"
	printf "${LL}${vertical_offset}${LR}\n\n"
}

function print_lvm_crypted() {
	printf "lvm_crypted:\t"
	[ ${lvm_1} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ ${lvm_2} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	printf "\n"
}

function print_ssh() {
	printf "ssh_server:\t"
	[ ${ssh_2} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ ${ssh_2} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ ${ssh_3} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	printf "\n"
}

function print_ufw() {
	printf "Firewall:\t"
	[ ${ufw_1} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ ${ufw_2} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
	[ ${ufw_3} == 1 ] && printf "${SUCCESS}" || printf "${FAILED}"
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
}

function print_result() {
	print_mandatory
}

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
#> Main

function basic_config() {
	if [ -z ${LOGIN} ]; then
		p_error "Please enter your login in the config file"
	else
		p_info "Welcome ${LOGIN}."
	fi
}

function check() {
	check_mandatory
}

function main() {
	tabs 20
	clear
	check_root
	basic_config
	check
	print_result
}

main
#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
