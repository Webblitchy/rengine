<p align="center">
<a href="https://rengine.wiki"><img src=".github/screenshots/banner.gif" alt=""/></a>
</p>


<h3>reNgine++<br>More than just recon!</h3>
<h4>The only web application recon tool you will ever need!</h4>

<p>Quickly discover the attack surface, and identify vulnerabilities using highly customizable and powerful scan engines.
Enjoy peace of mind with reNgine's continuous monitoring, deeper reconnaissance, and open-source powered Vulnerability Scanner.</p>

<h4>What is reNgine++ ?</h4>
<p align="left">
reNgine++ is a fork of <a href="https://github.com/yogeshojha/rengine">reNgine</a>. Besides beeing a powerful web application reconnaissance suite and having a modern interface, it adds a lot of features such as:
  
  - An internal network scanner, communicating to an <a href="https://github.com/Webblitchy/rengine-agent">internal agent</a> installed inside a network
  - A state associated with each pentest to know which step is the next one
  - A full company report engine, highly customisable with latex templates*
  - Few bugs fixed

\* Original reNgine provides a report engine too, but it is only for one scan and does not handle templates.

reNgine++ makes it easy for penetration testers and security auditors to gather reconnaissance data with bare minimal configuration.
</p>

---

## How to use

### Make an internal scan
1. Install the <a href="https://github.com/Webblitchy/rengine-agent">internal agent</a> in a local network by following the instructions in the project README
2. Add the generated SSH key in the reNgine server
3. Add the agent address from the menu `Add or Import Targets`
4. Start a scan for example with the engine "Port scan only" with the new target created, from the `Targets` menu
5. Results (such as Internal IPs) are shown in the `Target Summary` visible from the `Scan History`
   
<img alt="Internal scan" src="/.github/screenshots/Add_internal_target.png" width="50%">

### Change a pentest status
1. Go to the `Organization` menu
2. Add a new organization
3. From the organization list you can change the `Testing status`
   
<img alt="Pentest status" src="/.github/screenshots/Testing_status.png" width="50%">

### Generate a global report
1. Go to the `Organization` menu
2. Click on `Download Example Template`
3. Edit the template as you wish
4. Create or edit an organization
5. Import your new template by clicking on `Import Latex template`
6. Do some scans
7. From the `Organization` menu, download the report using the download button on the company line
<img alt="Global report" src="/.github/screenshots/Download_report.png" width="50%">

### Other
Despite these awesome new features, the interface and the mechanics remains the same hence the original documentation is still valid: <a href="https://rengine.wiki">rengine.wiki</a>

---

## Quick Installation

1. Clone this repo

    ```bash
    git clone https://github.com/Webblitchy/rengine && cd rengine
    ```

1. Run the installation script, Please keep an eye for any prompt, you will also be asked for username and password for reNgine.

    ```bash
    sudo chmod +x install.sh
    sudo ./install.sh
    ```

**reNgine can now be accessed from <https://127.0.0.1> or if you're on the VPS <https://your_vps_ip_address>**

---

## Screenshots from original rengine

### Scan Results

![](.github/screenshots/scan_results.gif)

### General Usage

<img src="https://user-images.githubusercontent.com/17223002/164993781-b6012995-522b-480a-a8bf-911193d35894.gif">

### Initiating Subscan

<img src="https://user-images.githubusercontent.com/17223002/164993749-1ad343d6-8ce7-43d6-aee7-b3add0321da7.gif">

### Recon Data filtering

<img src="https://user-images.githubusercontent.com/17223002/164993687-b63f3de8-e033-4ac0-808e-a2aa377d3cf8.gif">

### Report Generation

<img src="https://user-images.githubusercontent.com/17223002/164993689-c796c6cd-eb61-43f4-800d-08aba9740088.gif">

### Toolbox

<img src="https://user-images.githubusercontent.com/17223002/164993751-d687e88a-eb79-440f-9dc0-0ad006901620.gif">

### Adding Custom tool in Tools Arsenal

<img src="https://user-images.githubusercontent.com/17223002/164993670-466f6459-9499-498b-a9bd-526476d735a7.gif">

---


## License

Distributed under the GNU GPL v3 License. See [LICENSE](LICENSE) for more information.

