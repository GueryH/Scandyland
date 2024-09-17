#!bin/bash
Scandinavia="
 Welcome to:
 +-+ +-+ +-+ +-+ +-+ +-+ +-+ +-+ +-+ +-+
 |S| |C| |A| |N| |D| |Y| |L| |A| |N| |D|
 +-+ +-+ +-+ +-+ +-+ +-+ +-+ +-+ +-+ +-+
 "
LOCATION=$(pwd)
SYSFOLDER="$LOCATION/Sysfolder"
UserFolder="$LOCATION/Results"

Dial_x="	<x>"
Dial_o="	<o>"
RED='\033[0;31m' # Text Red Color
NC='\033[0m' # Regular Text Color
NETWORK="0.0.0.0"

HostIP=$(hostname -I)
OnlineIPs=""
User=$(whoami)
Mode="Basic"
OldIFS=$IFS
PassFile="./Resources/Cred/10000Pass.txt"
NamesFile="./Resources/Cred/names.txt"
BFs="hydra medusa"
BFServices="ftp ssh rdp telnet"

GetRed() {
    # outputs $1 in red
    echo -e "${RED}$1${NC}"
}

FindDataInResults(){
    # Prompt the user to type in the string they wish to find
    echo -e "\n$Dial_o Type in the string you wish to find:"
    read FindThisData

    # Display the string that the user is searching for
    echo -e "$Dial_o Looking for:\n$FindThisData"

    # Search for the string (case-insensitive) in the Results.txt file and display the results
    grepres=$(grep -i "$FindThisData" "$UserFolder"/Results.txt)
    if [ "$grepres" != "" ]
    then
        echo -e "$grepres"
    else
        echo "No results"
    fi
    # Ask the user if they would like to search for anything else
    echo -e "\n$Dial_o Would you like to search for anything else? [y/n]"
    read searchagain

    # Handle the user's response
    case $searchagain in
        y|Y)
            # If yes, recursively call the function to search again
            FindDataInResults
        ;;
        n|N)
            # If no, quit the search process
            echo -e "$Dial_o Quitting search."
        ;;
        *)
            # If an unavailable option is selected, notify the user and quit the search process
            echo -e "$Dial_o Unavailable option. Quitting search."
        ;;
    esac
}


DataForIP() {
    # Search for scan results related to the provided IP address ($1) in ScanRes.txt
    res=$(grep "$1:" $UserFolder/ScanRes.txt)

    # Print a header for the scan data related to the IP address
    echo -e "---------------- Scan data for $1 ----------------"

    # Extract the list of open ports from the scan results, sorting them and removing duplicates
    open_ports=$(echo -e "$res" | awk -F":" '{print $2}' | awk '{print $1}' | sort -n | uniq)

    # Check for weak passwords related to the IP in WeakAccounts.txt, replacing the IP with "Port" in the output
    weak=$(grep "$1" "$UserFolder"/WeakAccounts.txt | sed "s/$1/Port/g")
    if [ "$weak" != "" ]; then
        echo -e "\n"
        echo "Weak password for service login detected"
        echo -e "$weak"
    fi

    # Set the Internal Field Separator (IFS) to newline to handle the list of ports
    IFS=$'\n'
    for port in $open_ports; do

        # Extract the service name and version associated with the port, removing leading whitespace
        service=$(echo -e "$res" | grep ":$port" | awk -F"ServiceName:" '{print $2}' | awk -F"\t" '{print $1}' | sed 's/^[[:space:]]*//')
        version=$(echo -e "$res" | grep ":$port" | awk -F"ServiceVersion:" '{print $2}' | awk -F"\t" '{print $1}' | sed 's/^[[:space:]]*//')

        # Print the details of the open port
        echo -e "\n-------- Port $port is open --------\nService:$service\nVersion:$version"
        # Extract any associated vulnerabilities (CVEs) with the port, sort and remove duplicates
        vulns=$(echo -e "$res" | grep ":$port" | grep "Vuln:" | awk -F"Vuln:" '{print $2}' | sed 's/^[[:space:]]*//' | sort | uniq)
        if [ "$vulns" != "" ]; then
            echo -e "\n"
            echo "Common Vulnerabilities and Exposures list:"
            echo -e "$vulns" | tr ' ' '\n' | column

            # Check for any available exploits related to the IP and port in Searchsploit.txt
            exploits=$(grep "$1:$port" $UserFolder/Searchsploit.txt | awk -F"Searchsploit:" '{print $2}')
            if [ "$exploits" != "" ]; then
                echo -e "\nAvailable exploits:"
                # Iterate through each exploit group and individual exploit
                IFS="	"
                for exploitgroup in $exploits; do
                    IFS="+"
                    for exploit in $exploitgroup; do
                        echo -e "$exploit" | sed 's/^[ \t]*//' | column
                        IFS="	"
                    done
                done
            fi
        fi
    done

    # Print a footer indicating the end of the scan data
    echo -e "\n---------------- End of data ----------------\n\n"
}


DisplayFindings() {

    # Loop through each IP address stored in the OnlineIPs variable
    for IP in $OnlineIPs; do

        # Call the DataForIP function to display scan data for the current IP
        DataForIP "$IP"

    done
}


ZipAndDelete(){

    zip -r Results.zip ./Results > /dev/null 2>&1
    rm -r $UserFolder > /dev/null 2>&1
    rm -r $SYSFOLDER > /dev/null 2>&1
}

TestForWeakPasswords() {

    echo -e "$Dial_o Analyzing passwords strength"
    
    Address="$1"  # Assign the first argument to 'Address'
    Service="$2"  # Assign the second argument to 'Service'
    PortNumber="$3" # Assign the third argument to 'PortNumber'
    
    # Loop through each brute-force tool in the list "$BFs"
    for BF in $BFs; do
        # Retrieve the brute-force command from the resource file based on the tool and service
        Com=$(grep -i "$BF" "$LOCATION"/Resources/BF/BFCom.txt | grep -i "$Service" | awk -F"	" '{print $2}') > /dev/null 2>&1

        # If a command is found, execute it
        if [ "$Com" != "" ]; then
            eval $Com
        fi
    done

    # Check if the brute-force result file exists
    if [ -e "$SYSFOLDER"/BFRes.txt ]; then
        # Search for any lines containing the word "password" in the result file
        if grep -qi "password" "$SYSFOLDER"/BFRes.txt; then
            # Extract all lines with the word "password"
            Output=$(grep -i "password" "$SYSFOLDER"/BFRes.txt)

            IFS=$'\n'  # Set IFS to newline to handle multiline output

            # Loop through each line in the extracted output
            for l in $Output; do
                # Determine the format and extract account name and password accordingly
                if [[ $l == *"ACCOUNT FOUND"* ]]; then
                    AccountName=$(echo $l | awk -F "User: " '{print $2}' | awk '{print $1}')
                    Password=$(echo $l | awk -F "Password: " '{print $2}' | awk '{print $1}')
                else
                    AccountName=$(echo $l | awk -F "login: " '{print $2}' | awk '{print $1}')
                    Password=$(echo $l | awk -F "password: " '{print $2}' | awk '{print $1}')
                fi

                # Append weak account details to the "Weaks.txt" file
                echo "$Address:$PortNumber	$Service	$AccountName	$Password" >> "$SYSFOLDER"/Weaks.txt
            done

            IFS=$' '  # Reset IFS to default (space, tab, newline)

            # Sort "Weaks.txt", remove duplicates, and save the result to "WeakAccounts.txt"
            sort "$SYSFOLDER"/Weaks.txt | uniq > "$UserFolder"/WeakAccounts.txt
        fi
    fi
}




# Function to get a list of all online IPs
Scan() {

    echo -e "$Dial_o Looking for online machines"
    
    # Get all online IPs in the network specified by "$NETWORK" using nmap's ping scan (-sP)
    OnlineIPs=$(nmap -sP "$NETWORK" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')

    # Check if any IP addresses were found online
    if [ -n "$OnlineIPs" ]; then
        # Display the list of online IPs with color formatting
        echo -e "$Dial_o Currently online:\n$Dial_o ${RED}$OnlineIPs${NC}"

        # Loop through each online IP address found by nmap
        for IP in $OnlineIPs; do
            echo -e "\n$Dial_o Scanning IP: $IP"
            
            # Perform a detailed masscan and nmap scan on each online IP
            MasscanScan "$IP"
            NmapScan "$IP"
        done
    else
        # If no online IPs were found, display a message and exit the script
        echo -e "$Dial_x No online machines were found at the moment.\nGoodbye."
        exit
    fi
}

# Function to scan for open UDP ports on a specified IP using masscan
MasscanScan() {
    echo -e "$Dial_o Searching for UDP ports"
    
    # Store the IP address passed as the first argument into a local variable
    local IPinLoop="$1"
    
    # Run masscan on the specified IP to scan for open UDP ports in the range 1-65535
    # The scan is performed at a rate of 1000 packets per second, and the results are output to a file
    masscan $IPinLoop -pU:1-65535 --rate=1000 -oG "$SYSFOLDER"/masscan_udp.txt > /dev/null 2>&1
    
    # Extract the list of open UDP ports from the masscan output
    local res=$(grep -i "Timestamp" "$SYSFOLDER"/masscan_udp.txt | awk '{print $7}')
    
    # If open ports are found, process each port
    if [ -n "$res" ]; then
        for PortLine in $res; do
            # Extract the port number from the masscan output
            port=$(echo "$PortLine" | awk -F"/" '{print $1}')
            echo -e "$Dial_o Port $port is open"
            
            # Look up the service name associated with the port from a resource file
            servicename=$(grep -w "$port" ./Resources/UDPPorts.txt | awk '{$1=""; print $0}')
            
            # Extract the service version from the masscan output
            serviceversion=$(echo "$PortLine" | awk -F"/" '{print $5}')
            
            # Retrieve vulnerability data for the IP and port using NmapVulns function
            VulnData=$(NmapVulns $IPinLoop $port)
            
            # Append the scan results, including IP, port, service name, version, and vulnerabilities, to the ScanRes.txt file
            echo -e "$IPinLoop:$port	PortType:UDP	ServiceName:$servicename	ServiceVersion:$serviceversion	$VulnData" >> "$UserFolder"/ScanRes.txt
        done
    fi
}


NmapScan() {
	
	# The IP address to scan is passed as an argument and stored in the variable 'IPinLoop'
	local IPinLoop="$1"

	# Run an Nmap scan on the specified IP to check for open ports (initially scanning for ports 21-23, typically FTP, Telnet)
	OpenPortsNumber=$(timeout 60 nmap -Pn $IPinLoop -p- | grep "/tcp" | awk -F"/tcp" '{print $1}')
	
	# Check if the Nmap scan timed out (exit code 124 indicates a timeout)
	if [[ $? -eq 124 ]]; then
		# If the scan timed out, print a timeout message
		echo "$Dial_x Timeout: nmap scan of IP:$IPinLoop."
	else
		# If the scan was successful, proceed to analyze each open port found
		for Port in $OpenPortsNumber; do
			# Inform the user that the service version on the open port is being scanned
            echo -e "$Dial_o Port $Port is open \n$Dial_o Detecting service version"

			# Run another Nmap scan to detect the service version on the open port
			PortService=$(timeout 120 nmap -Pn -sV $IPinLoop -p$Port | grep "/tcp" | awk '{$2="";print $0}' | sort | uniq | awk -F"$Port/tcp " '{print $2}' | awk '{$1=$1;print}')

			# Extract the service name from the scan result
			ServName=$(echo $PortService | awk '{print $1}')
			# Extract the service version by removing the service name from the scan result
			ServVersion=$(echo $PortService | sed "s/$ServName //g")

			# Check if the service version scan timed out
			if [[ $? -eq 124 ]]; then
				# If the scan timed out, print a timeout message
				echo "$Dial_x The nmap command was terminated because it took too long to execute."
			else
				# If the scan was successful, test for weak passwords on the detected service
                if [[ "$BFServices" == *"$ServName"* ]]; then
				    TestForWeakPasswords $IPinLoop $ServName $Port 
                fi
				
				# If the scan mode is set to "Full", perform additional vulnerability scanning
				if [ "$Mode" == "Full" ]; then
					VulnData=$(NmapVulns $IPinLoop $Port)
                    echo -e "$IPinLoop:$Port	ServiceName:$ServName	ServiceVersion:$ServVersion	$VulnData" >> "$UserFolder"/ScanRes.txt
				fi
			fi
		done
	fi
}



NmapVulns(){
    
    # Perform an Nmap scan on the specified IP and port to detect vulnerabilities using the "vuln" script
    Vulnerabilities=$(timeout 120 nmap -sV --script="vuln" $1 -p$2 | grep -oE 'CVE-[0-9]{4}-[0-9]{4,7}' | sort | uniq | tr '\n' ' ' | sed 's/  / /g')
    
    # Check if the Nmap vulnerability scan timed out (exit code 124 indicates a timeout)
    if [[ $? -eq 124 ]]; then
        # If the scan timed out, print a timeout message
        echo "$Dial_x Timeout: nmap vulnerability detection of port:$2 was terminated."
    else
        # If vulnerabilities were found, append them to the scan data
        if [ -n "$Vulnerabilities" ]; then
            # Append the detected vulnerabilities to the existing scan data
            echo -e "Vuln:$Vulnerabilities"
        fi
    fi
}



GetSearchsploits(){
    
    # Inform the user that the search for vulnerabilities with searchsploit is starting
    echo -e "$Dial_o Searching for vulnerabilities with searchsploit"

    # Extract the vulnerability information from the "ScanRes.txt" file
    Txt=$(grep -i "Vuln:" "$UserFolder"/ScanRes.txt | awk -F"Vuln:" '{print $2}')

    # Set IFS (Internal Field Separator) to newline to handle line-by-line iteration
    IFS=$'\n'

    # Check if there is any vulnerability data to process
    if [ -n "$Txt" ]; then
        # Loop through each line of vulnerabilities
        for Cve_l in $Txt; do
            # Extract the IP addresses associated with the current CVE
            ip=$(grep "$Cve_l" "$UserFolder"/ScanRes.txt | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq)
            # Extract the port numbers associated with the current CVE
            port=$(grep "$Cve_l" "$UserFolder"/ScanRes.txt | awk -F"$ip:" '{print $2}' | awk '{print $1}' | sort | uniq)

            # Set IFS to space to handle each CVE code individually
            IFS=" "

            # Initialize the line variable to accumulate exploits
            line=""

            # Loop through each CVE code in the current line
            for Cve in $Cve_l; do
                # Extract the CVE code number (the part after "CVE-")
                CveCode=$(echo "$Cve" | awk -F"CVE-" '{print $2}' | awk -F" " '{print $1}')
                # Run the searchsploit command with the extracted CVE code
                res=$(searchsploit --cve $CveCode)

                # Check if the searchsploit output contains the word "Title", indicating relevant exploits
                if [[ "$res" == *Title* ]]; then
                    # If results are found, format them and append to the line variable
                    exploit=$(echo "$res" | head -n -2 | tail -n +4 | sed 's/  */ /g' | sed ':a;N;$!ba;s/\n/ + /g')
                    line+=$(echo -e "$exploit\t")
                fi
            done

            # If there are any exploits found, append them to "Searchsploit.txt"
            if [ -n "$line" ]; then
                echo -e "$ip:$port\tSearchsploit:$line" >> "$UserFolder"/Searchsploit.txt
            fi

            # Clear the line variable for the next iteration
            line=""
        done
    fi
}




SetScanMode() {
    
    # Display the mode selection prompt to the user
    echo -e "$Dial_o Select Mode:"
    echo -e "$Dial_o ${RED}B${NC}asic:	Scans TCP/UDP + Service Versions + Weak Passwords."
    echo -e "$Dial_o ${RED}F${NC}ull:	Basic + Vulnerability Analysis."

    # Read the user's mode selection input
    read UserModeSelection

    # Process the user's selection using a case statement
    case $UserModeSelection in
        f|F|FULL|Full|full)
            # If the user selects "Full" mode
            Mode="Full"  # Set the mode to "Full"
            echo -e "$Dial_o Full Mode Selected \n"
        ;;
        b|B|BASIC|Basic|basic)
            # If the user selects "Basic" mode
            echo -e "$Dial_o Basic Mode Selected \n"
        ;;
        *)
            # If the user selects an unrecognized option
            echo -e "$Dial_x Unidentified option selected, mode set: Basic \n"
        ;;
    esac
}


	
SetNetwork() {
    
    # Prompt the user to provide an IP address or IP range for scanning
    echo -e "$Dial_o Please provide an IP or IP range to scan"
    
    # Read the user's input and store it in the variable "NETWORK"
    read NETWORK
    
    # Call the function "IsNetworkValid" to validate the provided network input
    IsNetworkValid "$NETWORK"
    
    # Return the exit status of the "IsNetworkValid" function
    return $?
}

	
# Function to check if the input is a valid IPv4 address or IPv4 range (by chatGPT)
IsNetworkValid() {
    echo -e "$Dial_o Validating IP"
    local input="$1"

    # Regular expression for a valid IPv4 address
    local ip_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    
    # Regular expression for a valid IPv4 range (CIDR notation)
    local range_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])$"

    # Function to split a string by a delimiter and return an array
    split_string() {
        local IFS="$1"
        shift
        echo $*
    }

    # Check if the input matches either the IP address or the IP range format
    if [[ $input =~ $ip_regex ]];
    then
        # Verify that each octet is in the range 0-255
        local octets=($(split_string '.' $input))
        for octet in "${octets[@]}";
        do
            if (( octet < 0 || octet > 255 ));
            then
                #Invalid IP address
                return 1
            fi
        done
        echo "$Dial_o IP address accepted"
        return 0
    elif [[ $input =~ $range_regex ]];
    then
        # Verify that each octet is in the range 0-255
        local range=($(split_string '/' $input))
        local octets=($(split_string '.' ${range[0]}))
        for octet in "${octets[@]}";
        do
            if (( octet < 0 || octet > 255 ));
            then
                echo "$Dial_x Invalid IP range"
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}
function GetUserPasswordList() {

    # Prompt the user to decide whether to supply a custom passwords list
	echo -e "$Dial_o Would you like to supply a passwords list? [y/n]"
    
    # Read the user's decision
    read CustomPass
    
    # Handle the user's input using a case statement
    case $CustomPass in
        y|Y)
            # If the user chooses to supply a custom passwords list
			echo -e "$Dial_o Type in the full path of your passwords list"
            
            # Read the path to the user's password list
            read UserPassFile
            
            # Check if the file exists
            if [ ! -f $UserPassFile ]; then
                # If the file is not found, notify the user and recursively call the function to prompt again
                echo "$Dial_x File not found"
                GetUserPasswordList
            else
                # If the file exists, set it as the password file to be used
                echo -e '$Dial_o The passords list was updated'
                PassFile="$UserPassFile"
            fi
        ;;
        *)
            # If the user chooses not to supply a custom list, use the default list
            echo "$Dial_o System will use default list"
        ;;
    esac
}


function GetUserNamesList() {

    # Prompt the user to decide whether to supply a custom list of user names
	echo -e "$Dial_o Would you like to supply a list of user names? [y/n]"
    
    # Read the user's decision
    read CustomNamesList
    
    # Handle the user's input using a case statement
    case $CustomNamesList in
        y|Y)
            # If the user chooses to supply a custom list of user names
            echo "$Dial_o Type in the full path of your user names list"
            
            # Read the path to the user's user names list
            read UserNamesFile
            
            # Check if the file exists
            if [ ! -f $UserNamesFile ]; then
                # If the file is not found, notify the user and recursively call the function to prompt again
                echo "$Dial_x File not found"
                GetUserNamesList
            else
                # If the file exists, set it as the user names file to be used
                echo -e "$Dial_o The user names list was updated"
                NamesFile="$UserNamesFile"
            fi
        ;;
        *)
            # If the user chooses not to supply a custom list, use the default list
            echo "$Dial_o System will use default list"
        ;;
    esac
}


function MakeResultsFolder() {

    # Inform the user that a result folder is being created
    echo -e "$Dial_o Creating result folder."
    
    # Prompt the user to provide a name for the results folder or press enter for the default name
	echo -e "$Dial_o Please provide a name for your folder or press enter for default - /Results"
    
    # Read the user's input for the folder name
    read FolderName
    
    # Check if the user provided a name (i.e., the input is not empty)
    if [ -n "$FolderName" ]; then
        # If a name was provided, set the UserFolder variable to the new folder path
        UserFolder="$SYSFOLDER/$FolderName"
    fi
    
    # Create the results folder, using the provided name or default if none was given
    mkdir $UserFolder
}


function Init() {
    
    # Display a header message
    echo -e "${RED}$Scandinavia${NC}"
    
    # Check if the script is being run as the root user
    if [ "$User" = "root" ]; then
        
        # Prompt for and validate the network input
        SetNetwork
        
        # Check if SetNetwork was successful
        if [ $? = 0 ]; then
            # Create the SYSFOLDER directory
            mkdir $SYSFOLDER
            
            # Prompt for and set the scan mode
            SetScanMode
            
            # Create the results folder
            MakeResultsFolder
            
            # If the scan mode is "Full", get custom lists for passwords and usernames
            if [ "$Mode" == "Full" ]; then
                GetUserPasswordList
                GetUserNamesList
            fi
            
            # Start the network scanning process
            echo -e "$Dial_o Scanning the network."
            Scan
            
            # If the scan mode is "Full", get exploit data
            if [ "$Mode" == "Full" ]; then
                GetSearchsploits
            fi
            
            # Display findings and save to Results.txt
            DisplayFindings > "$UserFolder"/Results.txt

            # Ask the user if they want to view the results
            echo -e "$Dial_o Would you like to view the results?"
            read Answer
            case $Answer in
                y|Y)
                    # Display the results
                    cat "$UserFolder"/Results.txt
                ;;
            esac

            # Ask the user if they want to search the results
            echo -e "$Dial_o Would you like to search the results [y/n]?"
            read search
            case $search in
                y|Y)
                    # Search the results
                    FindDataInResults
                ;;
                n|N)
                    # Notify the user where to find the results
                    echo -e "Results available in $UserFolder zip file"
                ;;
                *)
                    # Notify the user where to find the results
                    echo -e "Results available in $UserFolder zip file"
                ;;
            esac

            # Zip the results and clean up
            ZipAndDelete
        else
            # If SetNetwork failed, prompt the user to retry or exit
            echo -e "$Dial_x The input provided is invalid.\n$Dial_x Type Y to retry or anything else to exit."
            read Retry
            case $Retry in
                Y)
                    # Retry initialization
                    Init
                ;;
                *)
                    # Exit the script
                    echo -e '$Dial_o Goodbye.'
                ;;
            esac
        fi
    else
        # Display an error if not running as root
        echo -e "$Dial_x You must be root to use this app."
    fi
}

Init