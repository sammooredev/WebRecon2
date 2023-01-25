package main

import (
	"bufio"
	"os"
	"os/exec"
	"sync"
	"time"
	//"fmt"
	"strconv"
	"github.com/DrSmithFr/go-console/pkg/input"
	"github.com/DrSmithFr/go-console/pkg/output"
	"github.com/DrSmithFr/go-console/pkg/style"
)

///
// Misc. Functions 
///

// function to print help
func PrintHelp() {
	out := output.NewConsoleOutput(true, nil)
	out.Writeln("<b>to run WebRecon, run the following commands. replace \\<name> with the name of the directory for the program you're testing.\n\n<comment>\t1. Create a directory for the test</comment>\n\t\t<info>$ mkdir -p ./Programs/\\<name>/recon-data\n</info>\n\t<comment>2. Create a domains.txt file containing the domains to test</comment>\n\t\t<info> $ vim ./Programs/\\<name>/recon-data/domains.txt</info>\n\n\t\t<info>NOTE - Each domain should be on a newline:\n\t\t\tfoo.com\n\t\t\tbar.com</info>\n\n\t<comment>3. Start enumeration on the program you set up</comment>\n\t\t<info>$ ./WebRecon \\<name></info>    * Note: \\<name> is the name of the directory in ./Programs/\\<name>")
	os.Exit(1)
}

/// function to check whether user input contains a value. 
func CheckUserInput() {
	if len(os.Args) == 1 {
		PrintHelp()
	}
}

// function to execute cmd commands
func ExecuteCmd() {

}

// function to build a new directory for a recon scan 
func BuildNewProgramDirectory(program_name string, date string) {
	out := output.NewConsoleOutput(true, nil)
	cmd := "mkdir -p ./Programs/" + program_name + "/" + date
	exec.Command("bash", "-c", cmd).Output()
	out.Writeln("<info>INFO - Created an output folder for: " + "<u>" + program_name + "</u>" + " -- (./Programs/" + program_name + "/" + date + ")</info>")
}

// function to check whether a domains list exists. if it does, it prints out the domains to be in that file. Return a string array of the domains
func CheckDomainsList(arg1 string) ([]string) {
	out := output.NewConsoleOutput(true, nil)
	var domains []string
	domains_list, err := os.Open("./Programs/" + arg1 + "/recon-data/domains.txt")
	if err != nil {
		out.Writeln("\n<error>ERROR! - Did you add a domains.txt file to ./Programs/" + arg1 + "/recon-data/domains.txt </error>")
		os.Exit(1)
	} else {
		defer domains_list.Close()
		scanner := bufio.NewScanner(domains_list)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			domains = append(domains, scanner.Text())
		}
		out.Writeln("\n<info><b>Domains to be tested: </info></b>")
		for _, a := range domains {
			out.Writeln("\t<comment>" + a + "</comment>")
		}
		out.Writeln("\n")
		
	}
	return domains
}

///
// Subdomain Enumeration Functions  
///

// function to generate potential subdomains using a list of publicly sourced subdomain names
func PotentialSubdomainsGenerator(domains []string, program string, date string, wg *sync.WaitGroup) {
	// cmd output styling
	out := output.NewConsoleOutput(true, nil)
	//open wordlist
	wordlist, _ := os.Open("./wordlists/httparchive_subdomains_2022_12_28.txt" )
	defer wordlist.Close()
	// read lines from wordlist
	scanner := bufio.NewScanner(wordlist)
	scanner.Split(bufio.ScanLines)
	var wordlist_lines []string
	for scanner.Scan() {
		// put lines into string array
		wordlist_lines = append(wordlist_lines, scanner.Text())
	}
	// split wordlist_line string array into multiple slices
	var divided [][]string

	chunkSize := len(wordlist_lines) / 20

	for i := 0; i < len(wordlist_lines); i += chunkSize {
		end := i + chunkSize
		
		if end > len(wordlist_lines) {
			end = len(wordlist_lines)
		}

		divided = append(divided, wordlist_lines[i:end])
	}
	
	// start generation
	out.Writeln("\n<info>INFO - Generating potential subdomains from file ./wordlists/httparchive_subdomains_2022_12_28.txt</info>")
	// subdomains_generated_count = count total number of subdomains generated, theads_count = number of threads generated.
	var subdomains_generated_count int
	var threads_count int
	subdomains_generated_count = 0
	threads_count = 0
	// start go routine waitgroup
	var wg2 sync.WaitGroup
	//create a worker for each domain in domains.txt
	//wg2.Add(len(domains))
	
	for _, domain := range domains {
		// for string arrays in divided
		for _, i := range divided {
			wg2.Add(1)
			foo := i 
			//fmt.Printf("%#v\n", foo)
			go func(domain string) {
				//fmt.Println("started thread")
				// create output file for each domain
				threads_count += 1
				
				output_file, err := os.OpenFile("./Programs/" + program + "/" + date + "/" + domain + "sub-generator" + strconv.Itoa(threads_count) + ".out", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					out.Writeln("<error>ERROR! - Couldnt create subdomain generator output file \"./Programs/" + program + "/" + date + "/" + domain + "sub-generator." + strconv.Itoa(threads_count) + ".out\"</error>")
					os.Exit(1)
				}
		
				defer wg2.Done()
				for _, line := range foo {
					subdomains_generated_count += 1
					//fmt.Printf("\t\t\r %d subdomains generated.", subdomains_generated_count)
					output_file.WriteString(line + "." + domain + "\n")
				}
			} (domain)
		}
	}
	wg2.Wait()
	wg.Done()
}


// function to run amass.
//func RunAmass(program_name string, date string, wg *sync.WaitGroup) {
//	out := output.NewConsoleOutput(true, nil)
//	out.Writeln("\n<info>INFO - Executing Amass against " + program_name + "</info>")
//	
//	cmd := exec.Command("bash", "-c", "amass enum -timeout 30 -df ./Programs/" + program_name + "/recon-data/domains.txt | tee -a ./Programs/" + program_name + "/" + date + "/amass.out")
//	stdout, _ := cmd.StdoutPipe()
//	cmd.Start()
//	oneByte := make([]byte, 100)
//	num := 1
//	for {
//		_, err := stdout.Read(oneByte)
//		if err != nil {
//			fmt.Printf(err.Error())
//			break
//		}
//		r := bufio.NewReader(stdout)
//		line, _, _ := r.ReadLine()
//		fmt.Println(string(line))
//		num = num + 1
//		if num > 3 {
//			os.Exit(0)
//		}
//	}
//
//	cmd.Wait()
//	wg.Done()
//}


func main() {
	// cmd output styling stuff
	in := input.NewArgvInput(nil)
	out := output.NewConsoleOutput(true, nil)
	io := style.NewGoStyler(in, out)

	// declare variables
	var wg sync.WaitGroup // for running cmd commands simultaneously 
	var arg1 string // to store the <Program> arguement when WebRecon is ran (./WebRecon <arguement>)

	// print title
	io.Title("WebRecon - your moms favorite recon script")
	
	// check user inputted an arguement (./WebRecon arguement). if not, print help & exit, else continue
	CheckUserInput()
	
	// get program name as argument
	arg1 = os.Args[1]
	
	// get date
	date := time.Now().Format("01-02-2006")

	// check domains list exists, has content, and output the domains to be tested
	// the function returns a string array of the domains to be tested. the "domains" variable is set to this string array.
	domains := CheckDomainsList(arg1)

	// build directory structure for new program
	BuildNewProgramDirectory(arg1, date)
	
	////                    ////
	//  start of enumeration  //
	////    				////

	// generate subdomains, run amass, run subfinder, run X simultaneously. 
	// run subdomain generator 
	go PotentialSubdomainsGenerator(domains, arg1, date, &wg)
	wg.Add(1)
//	go RunAmass(arg1, date, &wg)
//	wg.Add(1)
	wg.Wait()
}