

----------------------------------------------------------------------

GhostWP Injector V2 Developed by The Intrusion Team

----------------------------------------------------------------------

Features
-------------------------
- Detects if wordpress site is reachable
- Detects if XML-RPC is enabled 
- Multi threaded brute-forcer set option with --workers [number_of_workers]
- Single threaded mode, don't specify --workers flag
- Visual UI progress bar tracks password attempts
- Build a wordlist option --breachfile BREACHFILE and --dehashed uses leaked credentials found on the darkweb, while --wordlist uses a supplied password list
- Includes stealthy reverse shell option as well use --shell to inject a reverse PHP shell, use --LHOST LHOST and --LPORT LPORT to configure reverse shell
- If password is already known and you want to inject a reverse shell use --inject_only PASSWORD requires --LHOST LHOST and --LPORT LPORT to work
- Detects if user is Admin or not
- To use --dehashed API add flags --email DEHASHED EMAIL --apikey APIKEY --search TARGET EMAIL
- Added --Inject-only option if password is known to skip bruteforce attaack and try to get a shell account must be admin. useful for updating shell
- Added rate limit bypass for misconfigured servers only
- Remove backdoor from 404.php file using --remove_backdoor must also use --inject_only PASSWORD
- Added XML-RPC brute-forcer

TODO
-------------------------