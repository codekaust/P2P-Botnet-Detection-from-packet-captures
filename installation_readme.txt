~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
INSTALLING DEPENDENCIES
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On Debian based systems: (Ubuntu etc)

1. Make sure './install.sh' is executable by running in your shell the following command
        $ chmod +x ./install.sh
2. Execute "./install.sh", which does the following:
    i) Installs tshark, which will be used to process the pcap files
    ii) Sets up a python3 virtual enviornment, called 'venv'
3. Now, activate the virtualenv venv by:
	$ source ./venv/bin/activate


On Non-Debian based Systems: (Arch, CentOS, Fendora, etc)

1. Install 'tshark' using the OS specific package manager (pacman for arch, yum for Cent, etc)
2. Create a python3 virtual environment named 'venv' by running
        $ virtualenv --python=python3 venv
3. Activate the virtual environment by running
        $ source venv/bin/activate
4. Install the dependencies by running
        $ pip install -r requirement.txt

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
EVALUATING ON A TEST PCAP FILE
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Run the evaluation script on the pcap file
        $ python botnetdetect.py <path_to_pcap_file>
2. List of P2P BotNet hosts will be printed in the Shell, along with other log information. The list is also saved in the TXT file 'output.txt'
