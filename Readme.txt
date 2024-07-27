1. Open terminal in the project directory

2. Install the required dependencies: pip install -r requirements.txt

3. python serverE.py 

4. python clientE.py (In a new terminal window in same project directory, more the clients more will be the new terminal windows)

---------------------------------------------------------------------------------------------------------------
python serverE.py --help
usage: serverE.py [-h] [--host HOST] [--port PORT] [--key KEY] [--loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                  [--logfile LOGFILE]

Start the chat server.

options:
  -h, --help            show this help message and exit
  --host HOST           The IP address to bind the server to. (Default=0.0.0.0)
  --port PORT           The port number to bind the server to. (Default=12345)
  --key KEY             The secret key for encryption. (Default=mysecretpassword)
  --loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Set the logging level (Default: INFO)
  --logfile LOGFILE     Set the log file name. (Default: server.log)

------------------------------------------------------------------------------------------------------------------
python clientE.py --help
usage: clientE.py [-h] [--host HOST] [--port PORT] [--key KEY]

Connect to the chat server.

options:
  -h, --help   show this help message and exit
  --host HOST  The server's IP address.
  --port PORT  The port number of the server.
  --key KEY    The secret key for encryption.