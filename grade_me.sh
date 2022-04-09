#!/bin/bash

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
#= Bash Color

red="\x1b[38;5;160m"
reset="\x1b[0m"

function p_error() {
	printf "[${red}ERROR${reset}] $*\n"
	exit
}
#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
#= Utils
function check_root() {
	if [ ${EUID} != 0 ]; then
		p_error "Please run as root."
	fi
}

function source_config() {
	if [ -z ./config ]; then
		error "Config file note found"
	else
		source ./config
		if [ -z ${LOGIN} ]; then
			error "Please enter your login in the config file"
		else
			info "Welcome ${LOGIN}."
		fi
	fi
}
#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
#= hostname_check

function check_hostname() {
	[ "${LOGIN}42" -eq $(hostname) ] && hostname_ez = 0 || hostname_ez = 1
	hostname_ha
}

function check_LVM() {
	lsblk_out=$(lsblk)
}
#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
#= Main

function main() {
	check_root
	source_config
	check_mandatory
	check_LVM
}

main
#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#==#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
