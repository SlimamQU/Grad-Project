import os 
import sys
# import requests



try :
	os.system("echo start setting up ...")
	os.system("sudo apt update && upgrade")
	os.system("sudo apt-get install -y openjdk-17-jdk")
	os.system("echo finish installing java")
	os.system("sudo apt-get update & upgrade")
	os.system("sudo apt-get install -y flex bison gcc g++ make build-essential")
	os.system("echo finish installing flex bison gcc g++ make build-essential")
	os.system("sudo apt update && upgrade")
	os.system("sudo apt-get install -y graphviz graphviz-doc")
	os.system("echo finish installing graphviz and graphviz-doc")
	os.system("sudo apt-get install -y mysql-server mysql-client")
	os.system("sudo apt update && upgrade")
	os.system("sudo apt-get install -y shodan")
	os.system("echo finish installing mysql-client and mysql-server")
	os.system("cd ~")
	os.system("mkdir Tools")
	os.system("cd Tools")
	os.system("wget http://xsb.sourceforge.net/downloads/XSB.tar.gz")
	os.system("tar xzf XSB.tar.gz")
	os.system("wget https://people.cs.ksu.edu/~xou/argus/software/mulval/mulval_1_1.tar.gz")
	os.system("tar xzf mulval_1_1.tar.gz")
	os.system("mv XSB Tools/")
	os.system("cd Tools/")

	print("""

		add this path to this file ".bashrc"

		export JAVA_HOME=/usr/lib/jvm/java-1.17.0-openjdk-amd64
		export PATH=$PATH:$HOME/bin:$JAVA_HOME/bin

		export PATH=/home/**type your username**/Tools/XSB/bin:$PATH

		export MULVALROOT=/home/**type your username**/mulval
		export PATH=$MULVALROOT/bin:$MULVALROOT/utils:$PATH


		""")
	print("Setting up Tools hase been done")
	sys.exit()

except KeyboardInterrupt:
	print("\n Exiting program.")
	sys.exit()

except :
	print("make sure to exit")
	sys.exit()
