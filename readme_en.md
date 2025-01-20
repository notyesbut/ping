
# Game DNS Ping Tool

## Overview
**Game DNS Ping Tool** is a powerful utility designed for gamers to evaluate the performance of DNS servers. 
The tool provides metrics such as average ping, jitter, packet loss, traceroute analysis, and server geolocation.
With its graphical interface, users can identify the best DNS server for online gaming and monitor connection quality.

---

## Features
1. **Automatic Best DNS Selection**: Automatically picks the server with the lowest ping and jitter.
2. **Historical Data Tracking**: Stores previous results in a database for analysis.
3. **Real-Time Monitoring**: Perform continuous pings to assess server performance.
4. **Advanced Metrics**: Measures jitter, packet loss, and traceroute paths.
5. **Server Geolocation**: Maps the DNS servers on an interactive map.
6. **Visualization**: Displays results in graphs for easy comparison.
7. **Interactive GUI**: Simple and user-friendly graphical interface.

---

## Installation

### Prerequisites
1. Python 3.9 or later installed on your system.
2. Recommended package manager: `pip`.

### Required Libraries
Install dependencies using the following command:
```bash
pip install ping3 matplotlib geopy folium
```

### Additional Requirements
- **Windows**: Ensure `tracert` is available (default on Windows).
- **Linux/macOS**: Ensure `traceroute` is installed:
  ```bash
  sudo apt-get install traceroute  # Ubuntu/Debian
  sudo yum install traceroute      # Fedora
  ```

---

## First Launch Instructions

### Step 1: Download
1. Clone the repository using `git`:
   ```bash
   git clone https://github.com/your-repo-url
   cd your-repo-folder
   ```
2. Alternatively, download the `.zip` file and extract it.

### Step 2: Database Initialization
The application will automatically create a database file (`ping_history.db`) on the first run.

### Step 3: Run the Application
Launch the tool using:
```bash
python dns.py
```

### Step 4: Adding Servers (Optional)
You can add new DNS or gaming servers:
1. Click **"Add Server"** in the GUI.
2. Enter the name and IP address of the server.

---

## Features Overview

### Ping Testing
1. Specify the number of pings and timeout in seconds.
2. Click **"Start Ping"** to begin the process.

### View Results
1. **Table View**: Shows detailed metrics for each server.
2. **Graph View**: Displays average ping and jitter in a bar chart.
3. **Map View**: Plots server geolocations on an interactive map.

### Save and Load Servers
1. Save server configurations as a `.csv` file for reuse.
2. Load server lists from `.csv` files.

### Automatic DNS Selection
1. The tool automatically determines the best server based on metrics.
2. Users can optionally apply this DNS to their system (Windows/macOS).

---

## Troubleshooting

### Common Errors
1. **Database Errors**:
   - If `ping_history.db` is missing required columns, delete the file and restart the tool. It will recreate the database.
   ```bash
   rm ping_history.db
   ```

2. **Permissions Issues**:
   - For applying DNS changes, the tool may require administrative privileges:
     - **Windows**: Right-click the Python executable or your IDE and select **"Run as Administrator"**.
     - **Linux/macOS**: Use `sudo` to run the application.

3. **Traceroute Issues**:
   - Ensure `traceroute` (Linux/macOS) or `tracert` (Windows) is installed and accessible in your system's PATH.

---

## Support
For questions, suggestions, or contributions, contact the repository maintainer or submit a GitHub issue.

---

## License
This project is licensed under the MIT License. See `LICENSE` for more details.
