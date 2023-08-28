# WebRecon2

Yet Another Enumeration Tool

## Dependencies
### Golang
* tested on go1.20
* ran on unix system

## Installation
1. clone the repo:
```
$ git clone https://github.com/sammooredev/WebRecon2.git
```
2. cd into folder:
```
$ cd WebRecon2
```
3. you have two options, build the binary, or run with "go run":
```
$ go build 
$ ./WebRecon
```
```
$ go run main.go
```

### Tools that must be reachable within your $PATH:

Tools for subdomain enumeration and generation:
1. [amass](https://github.com/OWASP/Amass)
2. [subfinder](https://github.com/projectdiscovery/subfinder)
3. [dnsgen](https://github.com/ProjectAnte/dnsgen)

Tools for DNS bruteforcing (confirming that enumerated/generated subdomains actually exist):
1. [puredns](https://github.com/d3mondev/puredns)
    * [massdns](https://github.com/blechschmidt/massdns) - binary will also need to be accessible within your $PATH


## What does this tool do?
WebRecon2 utilizes the best tools available, each great at their own job, and combines them into a single script to automate a workflow that would typically be followed manually when performing subdomain enumeration. 

1. takes input as a list of domains (/Programs/\<program name>/recon-data/domains.txt)
    * foo.com 
    * bar.com
    * foo.bar.com
    * . . .
    
2. runs amass, subfinder against the domains & generates potential subdomains by prepending each word in "./wordlists/httparchive_subddomains_2022_12_28.txt" to each domain defined in the domains.txt file. This creates millions of potential subdomains. Currently you'll have to edit the code to change the wordlist thats used, but I plan to add an update feature in the future to pull the most recent files from https://wordlists.assetnote.io/. 

3. After amass, subfinder, and subdomains generation are complete, it combines the results of these 3 jobs into one file (all_enumerated_subdomains_combined_unique.txt)

4. A new directory is created for each domain in the domains.txt file, within each new directory the subdomains of that domain are placed into a new file (\<domain>-subdomains.out). 

4. One instance of puredns is run for each entry in domains.txt file, unless a subdomain of a domain already included in the domains.txt file is present. In the case that the domains.txt file includes entries as shown in step 1 (bar.com & foo.bar.com), only one instance of puredns is ran using the higher level domain (bar.com) as input. 

5. The output of puredns (a list of subdomains that had DNS records), are passed to dnsgen. This generates a new file containing permutations of puredns' output.

6. Puredns is then ran against the dnsgen output, to unconver even more subdomains.

7. Outputs a directory for each domain defined in domains.txt, containing results. A list of all unqiue subdomains for each domain combined is outputted as "final_list_unique.out"

Each tool generates a file as output and it isnt trashed by WebRecon2 after it's done running. 

## How to use

To create your own program and run WebRecon2 against it, perform the following:

1. Create the folder structure for the program within the ./Programs directory. [Starbucks](https://hackerone.com/starbucks?type=team) will be used as an example.
```
$ mkdir -p ./Programs/Starbucks/recon-data
```
2. Create a "domains.txt" within the recon-data directory you just created. Define a domain to be tested on each line.
```
$ vim ./Programs/Starbucks/recon-data/domains.txt
```  
3. Run WebRecon.
```
$ ./WebRecon Starbucks
```  
Once WebRecon2 has started running, it will create a directory using the current date to store its data.
The output folder will ultimately be structured like so:


If you wish to test WebRecon2 with a quickstart, the [Starbucks](https://hackerone.com/starbucks?type=team) program structure is included in the repo. Just do the following after installing and building. It will test a single domain (starbucks.com):
```
$ ./WebRecon Starbucks
``` 
## Usage Demo

![WebRecon2 Usage Demo](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhGVYfrFaMoriqQGmMoFgEUEA9_-lsP2CMUfJmRyk7vEVL-9HIIJPBI2eaegMmHsCR5QFXvVOCtssOewwYH8yCmu7l-qA2Nf0e6xyluoOQzMygftsqrK02qGK6Yln7uD3BD1yac4nHu8VutxcuYaRywzB5vWrSopjEZbGB4ik-sbFD4UW5AtSBlTg/s800/webrecon-demo.gif " WebRecon2 Usage Demo") 
![WebRecon2 Usage Demo](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEjA8d-rDQc0d9_XDVfYEmAVnI8ARucBVNaVV1OTlcYJzmoV53WO1urT4uegzwXPY_rS4ZP-V6J-OaDbBGOVL8bxsXAfQf-FgQMpN6-BH3Y4cCM6VYPTAXCXwToJexcBmWi8pz4nENwGz26QoKGhwM1-XBxj09ysz4tMfNXNozTRhGDCkLdWnveMXg/w615-h225/1.png "WebRecon2 Usage Demo")
![WebRecon2 Usage Demo](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgNvlfu8o_fWNE9VlIKP_BA0cX0QRK0Z5AjTSylQOwyFgeXF__4kQ_7GfIKk7rvuMdDydtlXwyuihdYe5b6uHkFLkREev28VTUC9uoYIZoZmhD7w3cQytI1xHW-Vv-GobIR0Oo_2eIMHSpimSkjth7nRYuNpYr8l6AeOD-iBQWYZiiKVXRNkBtGCQ/w599-h47/2.png "WebRecon2 Usage Demo")
* 1 hour 32 minutes run time
* 2570 unique hosts found

## Future Plans:
* add a function to check that the needed tools exists within $PATH and throw errors if not.
* use rapid7 fdns data 

## Resources: 

This tool is based off awesome blogs by [0xPatrik](https://twitter.com/0xpatrik?lang=en)
* [Subdomain Enumeration: 2019 Workflow](https://0xpatrik.com/subdomain-enumeration-2019/)
* [Subdomain Enumeration: Doing it a Bit Smarter](https://0xpatrik.com/subdomain-enumeration-smarter/)
