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

// function to combine all valid enumerated subdomains into one file "all_valid_subdomains_discovered.txt"
func CreateFileOfAllValidSubdomainsCombined(program_name string, date string, domains []string) {
	out := output.NewConsoleOutput(true, nil)
	// create string array of "<domain>-dnsgen-shuffledns.out" and "<domain>-shuffledns.out" file paths for each domain that was tested
	var files []string
	for _, domain := range domains {
		data_directory := "./Programs/" + program_name + "/" + date + "/top-level-domains/" + domain + "/" + domain + "-dnsgen-shuffledns.out"
		data_directory2 := "./Programs/" + program_name + "/" + date + "/top-level-domains/" + domain + "/" + domain + "-shuffledns.out"
		files = append(files, data_directory)
		files = append(files, data_directory2)
	}

	// create arbitrary sized buffer for data from files. then for each file, read its contents, write to buffer
 	var buf bytes.Buffer
	for _, file := range files {
		b, err := ioutil.ReadFile(file)
		if err != nil {
			log.Fatal(err)
		}

		buf.Write(b)
	}
	//create output file for non-unique "final_list.out"
	data_directory := "./Programs/" + program_name + "/" + date + "/"
	//output_file, err := os.OpenFile(data_directory + "final_list.out", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	//if err != nil {
	//	log.Fatal(err)
	//}

	// write buffer to it.
	err2 := ioutil.WriteFile(data_directory + "final_list.out", buf.Bytes(), 0644)
	if err2 != nil {
		log.Fatal(err2)
	}
	// remove duplicates and re-write
	wordlist_lines := WordlistToArray(data_directory + "final_list.out")
	unique_wordlist := removeDuplicateString(wordlist_lines)
	
	//create output file for "final_output_unique.out"
	output_file2, err3 := os.OpenFile(data_directory + "final_list_unique.out", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err3 != nil {
		log.Fatal(err3)
	}
	// write all unique lines from final_list.out to final_output_unqiue.out.
	for _, line := range unique_wordlist {
		output_file2.WriteString(line + "\n")
	}
	out.Writeln("\t<info>INFO - Created unique final list of subdomains for " + program_name + ". (" + data_directory + "final_list_unique.out)</info>")
}

// function to separate the all_enumerated_subdomains_combined_unique.txt into separate files based on the top level domain, and place them into their respective folders in /top-level-domains. This is needed so that shuffledns can be run on each root-domain, for the wildcard filtering.
func SeparateAllSubdomainsIntoSeparateFolders(program_name string, date string, domains []string) []string {
	in := input.NewArgvInput(nil)
	out := output.NewConsoleOutput(true, nil)
	io := style.NewGoStyler(in, out)
	// read all_enumerated_subdomains_combined_unique.txt into string array
	io.Section("Beginning subdomain separation (separating enumerated subdomains into separate folders by domain.)")
	all_unique_subdomains := WordlistToArray("./Programs/" + program_name + "/" + date + "/all_enumerated_subdomains_combined_unique.txt")
	
	sortedDomains := CatchRedundanciesInDomains(domains)
	
	// create directory for each top-level domain
	for _, domain := range sortedDomains {
		path := "./Programs/" + program_name + "/" + date + "/top-level-domains/" + domain
		err := os.Mkdir(path, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
		out.Writeln("\t<info>INFO - Created a new directory for " + domain + ". (./Programs/" + program_name + "/" + date + "/top-level-domains/" + domain + ")</info>")
	}


	// for value in top level domains string array:
		// grep all lines with top level domain from all subdomains string array
		// output to new file
	for _, top_level_domain := range sortedDomains {
		u, err := tld.Parse("https://" + top_level_domain + "/")
		if err != nil {
			log.Fatal(err)
		}
		//fmt.Printf("%50s = [ %s ] [ %s ] [ %s]\n",
		//	u, u.Subdomain, u.Domain, u.TLD)

		var regex *regexp.Regexp
		
		if len(u.Subdomain) > 0 {
			regex, _ = regexp.Compile(".*\\." + u.Subdomain + "\\." + u.Domain + "\\." + u.TLD + "$")
		} else {
			regex, _ = regexp.Compile(".*\\." + u.Domain + "\\." + u.TLD + "$")
		}
		//fmt.Println(regex.MatchString("foo.walt.disney.com"))
		
		// TODO: Test with queue implementation
		var subdomains_sorted_by_tld []string
		subdomains_sorted_by_tld = ConditionallyDequeueSubdomains(&all_unique_subdomains, regex)

		data_directory := "./Programs/" + program_name + "/" + date + "/"
		output_file, err := os.OpenFile(data_directory + "top-level-domains/" + top_level_domain + "/" + top_level_domain + "-subdomains.out", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		s := regex.String()
		out.Writeln("\t<info>INFO - Extracted values from all_enumerated_subdomains_combined_unique.txt matching regex " + s + " - Created file (" + data_directory + "top-level-domains/" + top_level_domain + "/" + top_level_domain + "-subdomains.out)</info>")

		for _, line := range subdomains_sorted_by_tld {
			output_file.WriteString(line + "\n")
		}
		//out.Writeln("\n<info>Beginning subdomain separation #" + strconv.Itoa(index) + "</info>")
	}
	return sortedDomains
}

func ConditionallyDequeueSubdomains(all_unique_subdomains *[]string, regex *regexp.Regexp) []string {
	subdomains_sorted_by_tld := make([]string, 0)
	for _, _ = range *all_unique_subdomains {
		if regex.MatchString((*all_unique_subdomains)[0]) == true {
			subdomains_sorted_by_tld = append(subdomains_sorted_by_tld, (*all_unique_subdomains)[0])
			*all_unique_subdomains = (*all_unique_subdomains)[1:]
		} else {
			requeue := (*all_unique_subdomains)[0]
			*all_unique_subdomains = (*all_unique_subdomains)[1:]
			*all_unique_subdomains = append((*all_unique_subdomains), requeue)
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
	in := input.NewArgvInput(nil)
	out := output.NewConsoleOutput(true, nil)
	io := style.NewGoStyler(in, out)
	wordlist_array := WordlistToArray("./wordlists/httparchive_subdomains_2022_12_28.txt")
	// split wordlist_line string array into multiple slices
	divided := Wordlist2DArrayGenerator(wordlist_array, 20)	
	// start generation
	out.Writeln("\t<info>INFO - Generating potential subdomains from file ./wordlists/httparchive_subdomains_2022_12_28.txt</info>")
	start := time.Now()
	SubdomainGenerator(domains, divided, program, date, wg, out, mute)
	time_elapsed := time.Now().Sub(start)
	total_generated := len(domains) * len(wordlist_array)
	str := fmt.Sprintf("Generating potential subdomains complete! Finished in %v, generating %d subdomains.", time_elapsed, total_generated)
	io.Success(str)
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
	in := input.NewArgvInput(nil)
	out := output.NewConsoleOutput(true, nil)
	io := style.NewGoStyler(in, out)
	out.Writeln("\t<info>INFO - Executing Amass against " + program_name + "</info>")
	
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
			//log.Printf(strconv.Itoa(count) + " amass out: %s", scanner.Text())
		}
		wg2.Done()
	} ()

	if err = cmd.Start(); err != nil {
		log.Fatal(err)
	}

	wg2.Wait()
	cmd.Wait()
	io.Success("Amass Enumeration Complete. " + strconv.Itoa(count) + " subdomains enumerated.")
	wg.Done()
}

// function to run subfinder.
func RunSubfinder(program_name string, date string, wg *sync.WaitGroup) {
	in := input.NewArgvInput(nil)
	out := output.NewConsoleOutput(true, nil)
	io := style.NewGoStyler(in, out)
	out.Writeln("\t<info>INFO - Executing subfinder against " + program_name + "</info>")
	
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
			//log.Printf(strconv.Itoa(count) + " subfinder out: %s", scanner.Text())
		}
		wg2.Done()
	} ()

	if err = cmd.Start(); err != nil {
		log.Fatal(err)
	}

	wg2.Wait()
	cmd.Wait() //bug where this also prints 0 
	io.Success("Subfinder Enumeration Complete. " + strconv.Itoa(count) + " subdomains enumerated.")
	wg.Done()
}


///
// Functions for doing bruteforce reverse DNS resolving
///

func RunShuffleDNS(program_name string, date string, domain string, mode int, wg *sync.WaitGroup) {
	out := output.NewConsoleOutput(true, nil)
	out.Writeln("\t<info>INFO - Executing shuffledns against " + domain + "</info>")
	
	program_path := "./Programs/" + program_name + "/" + date + "/top-level-domains/" + domain + "/"

	//select mode (changes cmd command value dependenant on mode value passed as arguement. 0 = run against enumerated, 1 = run against dnsgen output)
	var cmd *exec.Cmd
	var output_file *os.File
	if mode == 0 {
		//out.Writeln("shuffledns -t 50000 -r ./wordlists/resolvers.txt -d " + domain + " -list " + program_path + domain + "-subdomains.out")
		//cmd = exec.Command("bash", "-c", "shuffledns -t 50000 -r ./wordlists/resolvers.txt -d " + domain + " -list " + program_path + domain + "-subdomains.out")// -o " + program_path + domain + "-shuffledns.out")
		//puredns testing
		out.Writeln("puredns resolve " + program_path + domain + "-shuffledns.out -r ./wordlists/resolvers.txt")
		cmd = exec.Command("bash", "-c", "puredns resolve " + program_path + domain + "-subdomains.out -r ./wordlists/resolvers.txt")
		//create output file
		output_file, _ = os.OpenFile(program_path + domain + "-shuffledns.out", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	} else {
		//out.Writeln("shuffledns -t 50000 -r ./wordlists/resolvers.txt -d " + domain + " -list " + program_path + domain + "-dnsgen.out")
		//cmd = exec.Command("bash", "-c", "shuffledns -t 50000 -r ./wordlists/resolvers.txt -d " + domain + " -list " + program_path + domain + "-dnsgen.out")// + program_path + domain + "-dnsgen-shuffledns.out")
		//puredns testing
		out.Writeln("puredns resolve " + program_path + domain + "-dnsgen.out -r ./wordlists/resolvers.txt")
		cmd = exec.Command("bash", "-c", "puredns resolve " + program_path + domain + "-dnsgen.out -r ./wordlists/resolvers.txt")
		output_file, _ = os.OpenFile(program_path + domain + "-dnsgen-shuffledns.out", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}	

	
	stdout, _ := cmd.StdoutPipe()


	var wg2 sync.WaitGroup
	wg2.Add(1)
	

	var shufflednsout []string 
	count := 0
	scanner := bufio.NewScanner(stdout)
	go func() {
		for scanner.Scan() {
			count += 1 
			log.Printf(strconv.Itoa(count) + " shuffledns out: %s", scanner.Text())
			shufflednsout = append(shufflednsout, strings.ToLower(scanner.Text()) + "\n")
		}
		wg2.Done()
	} ()

	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}

	wg2.Wait()
	cmd.Wait() //bug where this also prints 0 
	for _, line := range shufflednsout {
		output_file.WriteString(line)
	} 
	out.Writeln("\t<info>INFO - Shuffledns Complete for " + domain + ". Found " + strconv.Itoa(count) + " valid subdomains. </info>")
	wg.Done()
}

///
// Functions for generating permutations of validated subdomains from shuffledns output
///

func RunDnsgen(program_name string, date string, domain string, wg *sync.WaitGroup) {
	out := output.NewConsoleOutput(true, nil)
	out.Writeln("\t<info>INFO - Executing dnsgen against " + domain + "</info>")
	
	program_path := "./Programs/" + program_name + "/" + date + "/top-level-domains/" + domain + "/"
	cmd := exec.Command("bash", "-c", "dnsgen " + program_path + domain + "-shuffledns.out | tee -a " + program_path + domain + "-dnsgen.out")
	
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
			//log.Printf(strconv.Itoa(count) + " %s", scanner.Text())
		}
		wg2.Done()
	} ()

	if err = cmd.Start(); err != nil {
		log.Fatal(err)
	}

	wg2.Wait()
	cmd.Wait() //bug where this also prints 0 
	out.Writeln("\t<info>INFO - dnsgen Complete for " + domain + ". Generated " + strconv.Itoa(count) + " potential subdomains. </info>")
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
	io.Title("WebRecon - subdomain enooooooooomeration")
	
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
	io.Section("Starting Subdomain Enumeration & Generating Potential Subdomains for " + arg1)
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
	start1 := time.Now()
	sortedDomains := SeparateAllSubdomainsIntoSeparateFolders(arg1, date, domains)
	time_elapsed1 := time.Now().Sub(start1)
	str := fmt.Sprintf("Separating subdomains Done! Finished in %v.", time_elapsed1)
	io.Success(str)

	///
	// Phase 2: validate subdomains exist via bruteforcing reverse dns lookups 
	///

	io.Section("Starting Reverse DNS Bruteforcing for " + arg1)
	// start clock to get runtime
	start2 := time.Now()
	// for each domain in sortedDomain (a list of domains which has redudancies removed)
	for _, domain := range sortedDomains {
		// run shuffledns for the domain - an instance of shuffledns is ran for each domain as its required for wildcard filtering.
		go RunShuffleDNS(arg1, date, domain, 0, &wg)
		wg.Add(1)
	}
	wg.Wait()
	// get time elapsed
	time_elapsed2 := time.Now().Sub(start2)
	// print out the commands completed and the runtime
	str2 := fmt.Sprintf("ShuffleDNS Done! Finished in %v.", time_elapsed2)
	io.Success(str2)

	///
	// Phase 3: Run dnsgen on each shuffledns output, generating permutations of the valid domains
	///
	io.Section("Starting generating permutations via dnsgen for " + arg1)
	// start clock to get runtime
	start3 := time.Now()
	for _, domain := range sortedDomains {
		//run dnsgen for each shuffledns output
		go RunDnsgen(arg1, date, domain, &wg)
		wg.Add(1)
	}
	wg.Wait()
	time_elapsed3 := time.Now().Sub(start3)
	// print out the commands completed and the runtime
	str3 := fmt.Sprintf("Permutation generation Done! Finished in %v.", time_elapsed3)
	io.Success(str3)

	///
	// Phase 4: Validate dnsgen output subdomains exist via bruteforcing reverse dns lookups
	///

	io.Section("Starting second round of ShuffleDNS against the dnsgen output for " + arg1)

	start4 := time.Now()
	// for each domain in sortedDomain (a list of domains which has redudancies removed)
	for _, domain := range sortedDomains {
		// run shuffledns for the domain - an instance of shuffledns is ran for each domain as its required for wildcard filtering.
		go RunShuffleDNS(arg1, date, domain, 1, &wg)
		wg.Add(1)
	}
	wg.Wait()
	// get time elapsed
	time_elapsed4 := time.Now().Sub(start4)
	// print out the commands completed and the runtime
	str4 := fmt.Sprintf("ShuffleDNS against dnsgen ouput done! Finished in %v.", time_elapsed4)
	io.Success(str4)

	///
	// Phase 5: Completion and clean up. Combine dnsgen outputs, place into <date> directory for test. print a goodbye message
	///
	io.Section("All enumeration and DNS bruteforcing complete. Creating output files for " + arg1 + "...")
	CreateFileOfAllValidSubdomainsCombined(arg1, date, sortedDomains)

}	