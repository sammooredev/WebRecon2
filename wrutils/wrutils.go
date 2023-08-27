package wrutils

import (
	"bufio"
	"bytes"
	"log"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/DrSmithFr/go-console/pkg/input"
	"github.com/DrSmithFr/go-console/pkg/output"
	"github.com/DrSmithFr/go-console/pkg/style"
	"github.com/jpillora/go-tld"
)

// SHELL SYNTAX FUNCTIONS
// function to print help
func PrintHelp() {
	out := output.NewConsoleOutput(true, nil)
	out.Writeln("<b>to run WebRecon, run the following commands. replace \\<name> with the name of the directory for the program you're testing.\n\n<comment>\t1. Create a directory for the test</comment>\n\t\t<info>$ mkdir -p ./Programs/\\<name>/recon-data\n</info>\n\t<comment>2. Create a domains.txt file containing the domains to test</comment>\n\t\t<info> $ vim ./Programs/\\<name>/recon-data/domains.txt</info>\n\n\t\t<info>NOTE - Each domain should be on a newline:\n\t\t\tfoo.com\n\t\t\tbar.com</info>\n\n\t<comment>3. Start enumeration on the program you set up</comment>\n\t\t<info>$ ./WebRecon \\<name></info>    * Note: \\<name> is the name of the directory in ./Programs/\\<name>")
	os.Exit(1)
}

// / function to check whether user input contains a value.
func CheckUserInput() {
	if len(os.Args) != 2 {
		PrintHelp()
	}
}

// function to check whether a domains list exists. if it does, it prints out the domains to be in that file. Return a string array of the domains
func CheckDomainsList(arg1 string) []string {
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

// HELPER FUNCTIONS FOR SUBDOMAIN PROCESSING
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

// pops off subdomains which match the regular expression regex; used to remove & write subdomains one TLD at a time
func ConditionallyDequeueSubdomains(all_unique_subdomains *[]string, regex *regexp.Regexp) []string {
	subdomains_sorted_by_tld := make([]string, 0)
	for range *all_unique_subdomains {
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

// convert domains string array into slice, order domains in slice by length (longest to smallest), catches edge cases where top level domains includes "google.com" "foo.google.com" so that it can match "foo.google.com" entries first. length (longest to smallest), catches edge cases where top level domains includes "google.com" "foo.google.com" so that it can match "foo.google.com" entries first.
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

// splits the string array "wordlist_lines" into mutliple smaller string arrays and places into 2d string array "wordlist_2d_array"
func Wordlist2DArrayGenerator(wordlist_array []string, chunks int) [][]string {
	var wordlist_2d_array [][]string
	chunkSize := len(wordlist_array) / chunks

	for i := 0; i < len(wordlist_array); i += chunkSize {
		end := math.Min(float64(i+chunkSize), float64(len(wordlist_array)))
		wordlist_2d_array = append(wordlist_2d_array, wordlist_array[i:int64(end)])
	}

	return wordlist_2d_array
}

// STORAGE & DIRECTORY FUNCTIONS
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

// function to combine files in the scan folder
func CombineFiles(program_name string, date string) {
	out := output.NewConsoleOutput(true, nil)
	// open output file (file of all subdomains combined)
	data_directory := "./Programs/" + program_name + "/" + date + "/"
	files := []string{data_directory + "sub-generator.out", data_directory + "amass.out", data_directory + "subfinder.out"} // add more entries here to combine more files
	var buf bytes.Buffer
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			log.Fatal(err)
		}

		buf.Write(b)
	}

	err := os.WriteFile(data_directory+"all_enumerated_subdomains_combined.txt", buf.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}
	// remove duplicates and re-write
	wordlist_lines := WordlistToArray(data_directory + "all_enumerated_subdomains_combined.txt")
	unique_wordlist := removeDuplicateString(wordlist_lines)

	//create output file
	output_file, err := os.OpenFile(data_directory+"all_enumerated_subdomains_combined_unique.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
	// create string array of "<domain>-dnsgen-puredns.out" and "<domain>-puredns.out" file paths for each domain that was tested
	var files []string
	for _, domain := range domains {
		data_directory := "./Programs/" + program_name + "/" + date + "/top-level-domains/" + domain + "/" + domain + "-dnsgen-puredns.out"
		data_directory2 := "./Programs/" + program_name + "/" + date + "/top-level-domains/" + domain + "/" + domain + "-puredns.out"
		files = append(files, data_directory)
		files = append(files, data_directory2)
	}

	// create arbitrary sized buffer for data from files. then for each file, read its contents, write to buffer
	var buf bytes.Buffer
	for _, file := range files {
		b, err := os.ReadFile(file)
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
	err2 := os.WriteFile(data_directory+"final_list.out", buf.Bytes(), 0644)
	if err2 != nil {
		log.Fatal(err2)
	}
	// remove duplicates and re-write
	wordlist_lines := WordlistToArray(data_directory + "final_list.out")
	unique_wordlist := removeDuplicateString(wordlist_lines)

	//create output file for "final_output_unique.out"
	output_file2, err3 := os.OpenFile(data_directory+"final_list_unique.out", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err3 != nil {
		log.Fatal(err3)
	}
	// write all unique lines from final_list.out to final_output_unqiue.out.
	for _, line := range unique_wordlist {
		output_file2.WriteString(line + "\n")
	}
	out.Writeln("\t<info>INFO - Created unique final list of subdomains for " + program_name + ". (" + data_directory + "final_list_unique.out)</info>")
}

// function to separate the all_enumerated_subdomains_combined_unique.txt into separate files based on the top level domain, and place them into their respective folders in /top-level-domains. This is needed so that puredns can be run on each root-domain, for the wildcard filtering.
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

		var subdomains_sorted_by_tld []string
		subdomains_sorted_by_tld = ConditionallyDequeueSubdomains(&all_unique_subdomains, regex)

		data_directory := "./Programs/" + program_name + "/" + date + "/"
		output_file, err := os.OpenFile(data_directory+"top-level-domains/"+top_level_domain+"/"+top_level_domain+"-subdomains.out", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
