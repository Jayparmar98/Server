<#
    dev-static-server.ps1
    ----------------------

    PURPOSE
    -------
    This script is a small static web server manager written in PowerShell.
    It automatically hosts an 'index.html' (and other static files) from a chosen
    folder, chooses a random free port on each start, and gives you a menu
    to control the server or run it silently in the background.

    MAIN FEATURES
    -------------
    - Serves static files (index.html, CSS, JS, images, etc.) from a root directory.
    - Random port selection at every "Start server".
    - HTTP by default (can be switched to HTTPS if you manually bind a certificate).
    - Localhost-only mode (works without admin).
    - Public/LAN mode (requires running PowerShell as Administrator).

    CONTROL OPTIONS (MENU MODE)
    ---------------------------
    When run in menu mode, the script shows an interactive menu with options:

      1) Start server
         - Starts a background HttpListener job that serves files from the root folder.
         - Picks a free random TCP port.
         - Builds the base URL (http://host:port/).
         - If running as Administrator and using "public" scope:
             * Adds a URL ACL via 'netsh http add urlacl'.
             * Opens a firewall rule for the selected port.
         - Optionally opens the URL in the default browser.
         - Logs all activity to a log file.

      2) Stop server
         - Forces the background job to stop and removes it.
         - If public scope and admin:
             * Removes the URL ACL.
             * Removes the firewall rule.
         - Stops the file watcher (auto-reload) if enabled.

      3) Restart server
         - Calls Stop then Start again.

      4) View current URL and port
         - Displays the URL the server is currently listening on.
         - Example: http://localhost:12345/

      5) Change root directory
         - Lets you choose a new folder to serve files from.
         - index.html in that folder becomes the default page.

      6) Toggle auto-open in browser
         - On/Off: whether to automatically open the URL in your default browser
           when the server starts.

      7) Show server status
         - Shows whether the server job is:
             * Running
             * Stopped
             * Not started
         - Also shows the current URL if available.

      8) View logs
         - Shows the last 40 lines of the log file (server.log) so you can see
           requests, errors, and status messages.

      9) Toggle auto-reload on file changes
         - Enables/disables a FileSystemWatcher on the root directory.
         - When files change, a message appears telling you to refresh your browser.

     10) Toggle access (localhost / public)
         - If NOT running as Administrator:
             * Always forced to 'localhost' only.
             * The script will display a warning and keep localhost mode.
         - If running as Administrator:
             * Switches between:
                 - localhost    → accessible only from this machine
                 - public/LAN   → accessible from other devices on the network
                   (URL ACL + firewall rule are used when public)

     11) Graceful shutdown
         - Stops the server if it is running.
         - Cleans up resources and exits the script.

     Q) Quit menu
         - Closes the menu loop.
         - If the server is running, it continues in the background until you stop it
           or close the PowerShell window.

    RUN MODES
    ---------
    The script supports multiple "modes" via the -Mode parameter:

    1) Mode = "launcher" (default)
       - Shows a small launcher menu:
           1) Foreground mode (new PowerShell window with full server menu)
           2) Background mode (run as silent daemon)
       - Foreground:
           * Opens a new PowerShell window and runs this script in "menu" mode.
       - Background:
           * Starts a hidden PowerShell process that runs this script in "daemon" mode.

    2) Mode = "menu"
       - Runs the full interactive menu in the current window.
       - This is where you see options 1–11 and Q.

    3) Mode = "daemon"
       - Intended for background (silent) use.
       - Starts the static server and keeps the process alive.
       - Writes info to:
           * server-background.pid   → PID of the daemon process.
           * server-background.json  → JSON with URL, port, scope, start time.
           * server-background.stop  → Presence of this file tells the daemon to stop.
       - The daemon periodically checks for the stop file and exits when it appears.

    4) Mode = "control"
       - Used to control an already running daemon from another PowerShell session.
       - Requires an -Action parameter:
           * -Action status
               - Shows whether the background process is running and prints info
                 from server-background.json (URL, port, scope, start time).
           * -Action url
               - Prints only the current background server URL.
           * -Action stop
               - Writes the stop file to signal the daemon to shut down.
               - Waits up to ~20 seconds for the process to exit, then cleans up
                 the pid/info/stop files.

    PERMISSIONS & BEHAVIOR
    ----------------------
    - As a normal (non-admin) user:
        * The server runs in localhost-only mode.
        * No firewall rules or URL ACLs are created.
        * You can still use all menu and background features, but the site is
          only accessible from the same machine.

    - As an Administrator:
        * You can switch the bind scope to "public", allowing:
            - Listening on all interfaces (LAN)
            - URL ACL configuration via netsh
            - Automatic firewall rule creation and cleanup
        * Other devices on your local network can access the server using
          your machine's IP and the chosen port.

    LOGGING
    -------
    - All major events (start, stop, errors, requests, watcher events, etc.) are
      written to "server.log" in the same folder as this script.
    - The log helps debug issues like failed binding, firewall problems,
      request paths, and file-serving errors.

#>
