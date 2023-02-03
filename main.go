package main

import (
	"bufio"
	"os"
	"os/exec"
	"sync"
	"time"
	"math"
	"bytes"
	"io/ioutil"
	"log"
	"fmt"
	"strconv"
	"sort"
	"strings"
	"regexp"
	"github.com/jpillora/go-tld"
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

// function to build a new directory for a recon scan 
func BuildNewProgramDirectory(program_name string, date string, domains []string) {
	// this should work on every OS, not just linux.
	out := output.NewConsoleOutput(true, nil)
	path := "./Programs/" + program_name + "/" + date + "/top-level-domains"
	
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
	// create directory for each top-level domain
	for _, domain := range domains {
		path := "./Programs/" + program_name + "/" + date + "/top-level-domains/" + domain
		err := os.Mkdir(path, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
	}

	out.Writeln("<info>INFO - Created an output folder for: " + "<u>" + program_name + "</u>" + " -- (./Programs/" + program_name + "/" + date + ")</info>")
	// original implementation:
	//cmd := "mkdir -p ./Programs/" + program_name + "/" + date
	//exec.Command("bash", "-c", cmd).Output()
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

// function to combine files in the scan folder
func CombineFiles(program_name string, date string) {
	out := output.NewConsoleOutput(true, nil)
	// open output file (file of all subdomains combined)
	data_directory := "./Programs/" + program_name + "/" + date + "/"
	files := []string{data_directory + "sub-generator.out", data_directory + "amass.out", data_directory + "subfinder.out"} // add more entries here to combine more files
 	var buf bytes.Buffer
	for _, file := range files {
		b, err := ioutil.ReadFile(file)
		if err != nil {
			log.Fatal(err)
		}

		buf.Write(b)
	}

	err := ioutil.WriteFile(data_directory + "all_enumerated_subdomains_combined.txt", buf.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}
	// remove duplicates and re-write
	wordlist_lines := WordlistToArray(data_directory + "all_enumerated_subdomains_combined.txt")
	unique_wordlist := removeDuplicateString(wordlist_lines)
	
	//create output file
	output_file, err := os.OpenFile(data_directory + "all_enumerated_subdomains_combined_unique.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		out.Writeln("<error>ERROR! \"</error>")
		os.Exit(1)
	}

	for _, line := range unique_wordlist {
		output_file.WriteString(line + "\n")
	}
}

// function to separate the all_enumerated_subdomains_combined_unique.txt into separate files based on the top level domain, and place them into their respective folders in /top-level-domains. This is needed so that shuffledns can be run on each root-domain, for the wildcard filtering.
func SeparateAllSubdomainsIntoSeparateFolders(program_name string, date string, domains []string) {
	// read all_enumerated_subdomains_combined_unique.txt into string array
	all_unique_subdomains := WordlistToArray("./Programs/" + program_name + "/" + date + "/all_enumerated_subdomains_combined_unique.txt")
	
	sortedDomains := CatchRedundanciesInDomains(domains)
	
	// for value in top level domains string array:
		// grep all lines with top level domain from all subdomains string array
		// output to new file
	for _, top_level_domain := range sortedDomains {
		u, err := tld.Parse("https://" + top_level_domain + "/")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%50s = [ %s ] [ %s ] [ %s]\n",
			u, u.Subdomain, u.Domain, u.TLD)

		var regex *regexp.Regexp
		
		if len(u.Subdomain) > 0 {
			regex, _ = regexp.Compile(".*\\." + u.Subdomain + "\\." + u.Domain + "\\." + u.TLD + "$")
		} else {
			regex, _ = regexp.Compile(".*\\." + u.Domain + "\\." + u.TLD + "$")
		}
		fmt.Println(regex.MatchString("foo.walt.disney.com"))
		
		// TODO: Test with queue implementation
		var subdomains_sorted_by_tld []string
		subdomains_sorted_by_tld = ConditionallyDequeueSubdomains(all_unique_subdomains, regex)

		data_directory := "./Programs/" + program_name + "/" + date + "/"
		output_file, err := os.OpenFile(data_directory + "top-level-domains/" + top_level_domain + "/" + top_level_domain + "-subdomains.out", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}

		for _, line := range subdomains_sorted_by_tld {
			output_file.WriteString(line + "\n")
		}
	}
}

func ConditionallyDequeueSubdomains(all_unique_subdomains []string, regex *regexp.Regexp) []string {
	subdomains_sorted_by_tld = make([]string, 0)
	for _, line := range all_unique_subdomains {
		if regex.MatchString(line) == true {
			subdomains_sorted_by_tld = append(subdomains_sorted_by_tld, line)
			all_unique_subdomains = all_unique_subdomains[1:]
		} else {
			requeue := all_unique_subdomains[0]
			all_unique_subdomains = all_unique_subdomains[1:]
			all_unique_subdomains = append(all_unique_subdomains, requeue)
		}
	}
	return subdomains_sorted_by_tld
}

// convert domains string array into slice, order domains in slice by// convert domains string array into slice, order domains in slice by length (longest to smallest), catches edge cases where top level domains includes "google.com" "foo.google.com" so that it can match "foo.google.com" entries first. length (longest to smallest), catches edge cases where top level domains includes "google.com" "foo.google.com" so that it can match "foo.google.com" entries first.
func CatchRedundanciesInDomains(domains []string) []string {
	sortedDomains := domains[:] // length sorting code modified from https://code-maven.com/slides/golang/sort-strings-by-length
	sort.Slice(sortedDomains, func(a, b int) bool {
		return len(sortedDomains[a]) < len(sortedDomains[b]) 
	})
	
	i, checkLen := 0, len(sortedDomains)
	for i < checkLen {
		for index, domain := range sortedDomains[i+1:] {
			if strings.Contains(domain, sortedDomains[i]) {
				sortedDomains = append(sortedDomains[:index+i+1], sortedDomains[index+i+2:]...)
				checkLen -= 1
			}
		}
		i += 1
	}
	return sortedDomains
}

// function to remove duplicates from a string array
func removeDuplicateString(strSlice []string) []string {
	// map to store unique keys - https://www.golinuxcloud.com/golang-concat-slices-unique/
	keys := make(map[string]bool)
	returnSlice := []string{}
	for _, item := range strSlice {
		if _, value := keys[item]; !value {
			keys[item] = true
			returnSlice = append(returnSlice, item)
		}
	}
	return returnSlice
}


///
// Subdomain Enumeration Functions  
///

//TODO: rethink data structures
//function to generate potential subdomains using a list of publicly sourced subdomain names
func PotentialSubdomainGeneratorMain(domains []string, program string, date string, wg *sync.WaitGroup, mute sync.Mutex) {
	// cmd output styling
	out := output.NewConsoleOutput(true, nil)
	wordlist_array := WordlistToArray("./wordlists/httparchive_subdomains_2022_12_28.txt")
	// split wordlist_line string array into multiple slices
	divided := Wordlist2DArrayGenerator(wordlist_array, 20)	
	// start generation
	out.Writeln("\n<info>INFO - Generating potential subdomains from file ./wordlists/httparchive_subdomains_2022_12_28.txt</info>")
	start := time.Now()
	SubdomainGenerator(domains, divided, program, date, wg, out, mute)
	time_elapsed := time.Now().Sub(start)
	total_generated := len(domains) * len(wordlist_array)
	str := fmt.Sprintf("\n<info>INFO - Done! Finished in %v, generating %d subdomains.", time_elapsed, total_generated)
	out.Writeln(str)
	wg.Done()
}

/* Opens a wordlist file and places each line into a string array. */
func WordlistToArray(wordlist_file_path string) []string {
	//open wordlist
	wordlist, _ := os.Open(wordlist_file_path)
	defer wordlist.Close()
	// read lines from wordlist
	scanner := bufio.NewScanner(wordlist)
	scanner.Split(bufio.ScanLines)
	var wordlist_lines []string
	for scanner.Scan() {
		// put lines into string array
		wordlist_lines = append(wordlist_lines, scanner.Text())
	}
	return wordlist_lines
}

// splits the string array "wordlist_lines" into mutliple smaller string arrays and places into 2d string array "wordlist_2d_array"
func Wordlist2DArrayGenerator(wordlist_array []string, chunks int) [][]string {
	var wordlist_2d_array [][]string
	chunkSize := len(wordlist_array) / chunks

	for i := 0; i < len(wordlist_array); i += chunkSize {
		end := math.Min(float64(i + chunkSize), float64(len(wordlist_array)))
		wordlist_2d_array = append(wordlist_2d_array, wordlist_array[i:int64(end)])
	}
	return wordlist_2d_array
} 

func SubdomainGenerator(domains []string, wordlist_2d_array [][]string,program string,
	date string, wg *sync.WaitGroup, out *output.ConsoleOutput, mute sync.Mutex) {
	// subdomains_generated_count = count total number of subdomains generated, threads_count = number of threads generated.
	var subdomains_generated_count int
	var threads_count int
	subdomains_generated_count = 0
	threads_count = 0
	// start go routine waitgroup
	var wg2 sync.WaitGroup
	//create a worker for each domain in domains.txt
	//wg2.Add(len(domains))
	// Lock writing
	mute.Lock()
	defer mute.Unlock()
	
	//create output file
	output_file, err := os.OpenFile("./Programs/" + program + "/" + date + "/sub-generator.out", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		out.Writeln("<error>ERROR! \"</error>")
		os.Exit(1)
	}

	for _, domain := range domains {
		// for string arrays in divided
		for _, i := range wordlist_2d_array {
			wg2.Add(1)
			foo := i 
			//fmt.Printf("%#v\n", foo)
			go func(domain string) {
				//fmt.Println("started thread")
				// create output file for each domain
				threads_count += 1
		
				defer wg2.Done()
				for _, line := range foo {
					subdomains_generated_count += 1

					output_file.WriteString(line + "." + domain + "\n")
				}
			} (domain)
		}
	}
	wg2.Wait()
}


// function to run amass.
func RunAmass(program_name string, date string, wg *sync.WaitGroup) {
	out := output.NewConsoleOutput(true, nil)
	out.Writeln("\n<info>INFO - Executing Amass against " + program_name + "</info>")
	
	cmd := exec.Command("bash", "-c", "amass enum -timeout 2 -df ./Programs/" + program_name + "/recon-data/domains.txt -o ./Programs/" + program_name + "/" + date + "/amass.out")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}

	var wg2 sync.WaitGroup
	wg2.Add(1)
	count := 0

	scanner := bufio.NewScanner(stdout)
	go func() {
		for scanner.Scan() {
			count += 1 
			log.Printf(strconv.Itoa(count) + " amass out: %s", scanner.Text())
		}
		wg2.Done()
	} ()

	if err = cmd.Start(); err != nil {
		log.Fatal(err)
	}

	wg2.Wait()
	cmd.Wait()
	out.Writeln("<info>INFO - Amass Enumeration Complete. " + strconv.Itoa(count) + " subdomains enumerated. </info>")
	wg.Done()
}

// function to run subfinder.
func RunSubfinder(program_name string, date string, wg *sync.WaitGroup) {
	out := output.NewConsoleOutput(true, nil)
	out.Writeln("\n<info>INFO - Executing subfinder against " + program_name + "</info>")
	
	cmd := exec.Command("bash", "-c", "subfinder -dL ./Programs/" + program_name + "/recon-data/domains.txt -o ./Programs/" + program_name + "/" + date + "/subfinder.out")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}

	var wg2 sync.WaitGroup
	wg2.Add(1)

	count := 0
	scanner := bufio.NewScanner(stdout)
	go func() {
		for scanner.Scan() {
			count += 1 
			log.Printf(strconv.Itoa(count) + " subfinder out: %s", scanner.Text())
		}
		wg2.Done()
	} ()

	if err = cmd.Start(); err != nil {
		log.Fatal(err)
	}

	wg2.Wait()
	cmd.Wait() //bug where this also prints 0 
	out.Writeln("<info>INFO - Subfinder Enumeration Complete. " + strconv.Itoa(count) + " subdomains enumerated. </info>")
	wg.Done()
}


///
// Functions for doing bruteforce reverse DNS resolving
///

func RunShuffleDNS(program_name string, date string, domain string, wg *sync.WaitGroup) {
	out := output.NewConsoleOutput(true, nil)
	out.Writeln("\n<info>INFO - Executing shuffledns against " + domain + "</info>")
	
	program_path := "./Programs/" + program_name + "/" + date + "/top-level-domains/" + domain + "/"
	cmd := exec.Command("bash", "-c", "shuffledns -r ./wordlists/resolvers.txt -d " + domain + " -list " + program_path + domain + "-subdomains.out -o " + program_path + domain + "-shuffledns.out")
	
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}

	var wg2 sync.WaitGroup
	wg2.Add(1)

	count := 0
	scanner := bufio.NewScanner(stdout)
	go func() {
		for scanner.Scan() {
			count += 1 
			log.Printf(strconv.Itoa(count) + " shuffledns out: %s", scanner.Text())
		}
		wg2.Done()
	} ()

	if err = cmd.Start(); err != nil {
		log.Fatal(err)
	}

	wg2.Wait()
	cmd.Wait() //bug where this also prints 0 
	out.Writeln("<info>INFO - Shuffledns Complete. </info>")
	wg.Done()
}


func main() {
	// cmd output styling stuff
	in := input.NewArgvInput(nil)
	out := output.NewConsoleOutput(true, nil)
	io := style.NewGoStyler(in, out)

	// declare variables
	var wg sync.WaitGroup // for running cmd commands simultaneously 
	var arg1 string // to store the <Program> arguement when WebRecon is ran (./WebRecon <arguement>)
	var mute sync.Mutex // to establish queue for writing using multiple threads

	// print title
	io.Title("WebRecon - bro she just not into you")
	
	// check user inputted an arguement (./WebRecon arguement). if not, print help & exit, else continue
	CheckUserInput()
	
	// get program name as argument
	arg1 = os.Args[1]
	
	// get date
	date := time.Now().Format("01-02-2006")

	// check domains list exists, has content, and output the domains to be tested
	// the function returns a string array of the domains to be tested. the "domains" variable is set to this string array.
	domains := CheckDomainsList(arg1)
	//CheckDomainsList(arg1)
	// build directory structure for new program
	BuildNewProgramDirectory(arg1, date, domains)
	
	////                    ////
	//  start of enumeration  //
	////    				////

	///
	// Phase 1: subdomain generation. - generate subdomains, run amass, run subfinder, run X simultaneously. 
	///
	
	go PotentialSubdomainGeneratorMain(domains, arg1, date, &wg, mute)
	wg.Add(1)
	go RunAmass(arg1, date, &wg)
	wg.Add(1)
	go RunSubfinder(arg1, date, &wg)
	wg.Add(1)
	wg.Wait()

	// this function combines all the files within the date directory for the scan (./Programs/Google/01-25-23/*) into one file, and removes duplicate entries. outputs the files: "all_enumerated_subdomains_combined.txt" & "all_enumerated_subdomains_combined_unique.txt"  
	CombineFiles(arg1, date)
	// this function separates "all_enumerated_subdomains_combined_unique.txt" into separate files by top-level-domain and places them into ./Programs/<program>/<date>/top-level-domain/<top-level-domain>/<top-level-domain>-subdomains.txt 
	SeparateAllSubdomainsIntoSeparateFolders(arg1, date, domains)


	///
	// Phase 2: validate subdomains exist via bruteforcing reverse dns lookups 
	///
	//for domain in range domains, run shuffledns
	for _, domain := range domains {
		go RunShuffleDNS(arg1, date, domain, &wg)
		wg.Add(1)
	}
	wg.Wait()
}	