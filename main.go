package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sammooredev/WebRecon/wrtools"
	"github.com/sammooredev/WebRecon/wrutils"

	"github.com/DrSmithFr/go-console/pkg/input"
	"github.com/DrSmithFr/go-console/pkg/output"
	"github.com/DrSmithFr/go-console/pkg/style"
)

// SHELL SYNTAX FUNCTIONS
// function to print help
func PrintHelp() {
	out := output.NewConsoleOutput(true, nil)
	out.Writeln("<b>to run WebRecon, run the following commands. replace \\<name> with program name of your choice.\n\n" +
		"<comment>\t1. Create a directory for the test</comment>\n" +
		"\t\t<info>$ mkdir -p ./Programs/\\<name>/recon-data</info>\n" +
		"\n\t<comment>2. Create a domains.txt file containing the domains to test</comment>\n" +
		"\t\t<info>$ vim ./Programs/\\<name>/recon-data/domains.txt</info>\n\n" +
		"\t\t<info>NOTE - Each domain should be on a newline:\n" +
		"\t\t\tfoo.com\n" +
		"\t\t\tbar.com</info>\n\n" +
		"\t<comment>3. Start enumeration on the program you set up</comment>\n" +
		"\t\t<info>$ ./WebRecon [flags] \\<name></info>    * Note: \\<name> is the name of the directory in ./Programs/\\<name>\n" +
		"\t\t\t<info>-atimeout    Maximum timeout for Amass (in minutes). Default 45 minutes</info>\n" +
		"\t\t\t<info>-tools       Comma-separated list of enum tools. Default all (subfinder,amass,sub-generator)</info>\n" +
		"\t\t\t<info>-wildcard    When enabled, runs PureDNS with wildcard filtering on (large time sink). Default false</info>\n" +
		"")
	os.Exit(1)
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

func ParseFlags() (uint, []string, bool, string) {
	// setup flags
	out := output.NewConsoleOutput(true, nil)
	atimeout := flag.Uint("atimeout", 45, "Max timeout to use for Amass")
	tools := flag.String("tools", "subfinder,amass,sub-generator", "Comma-separated list of enum tools (default subfinder,amass,sub-generator)")
	wildcard := flag.Bool("wildcard", false, "Whether or not to run PureDNS with wildcard filtering on")

	// check user inputted an argument (./WebRecon argument). if not, print help & exit, else continue
	flag.Parse()
	if len(flag.Args()) != 1 {
		PrintHelp()
	}

	// check supplied list is OK
	toolsList := strings.Split(*tools, ",")
	if len(toolsList) > 0 && len(toolsList) < 4 {
		validEntries := []string{"subfinder", "amass", "sub-generator"}
		for _, v := range toolsList {
			if !wrutils.SliceContainsString(validEntries, v) {
				out.Writeln("\n<error>ERROR! - Invalid tool " + v + " supplied.</error>")
				os.Exit(1)
			}
		}
	} else {
		out.Writeln("\n<error>ERROR! - Too many or no tools in list supplied to -tools flags. </error>")
		os.Exit(1)
	}

	return *atimeout, toolsList, *wildcard, flag.Args()[0]
}

// MAIN
func main() {
	// cmd output styling stuff
	in := input.NewArgvInput(nil)
	out := output.NewConsoleOutput(true, nil)
	io := style.NewGoStyler(in, out)

	// declare variables
	var wg sync.WaitGroup // for running cmd commands simultaneously
	var arg1 string       // to store the <Program> arguement when WebRecon is ran (./WebRecon <arguement>)
	var mute sync.Mutex   // to establish queue for writing using multiple threads

	// print title
	io.Title("WebRecon v2 - Subdomain enumeration made easy")

	// verify dependencies
	wrutils.VerifyDependencies()

	// get user input, including amass timeout and name of program
	atimeout, tools, wildcard, arg1 := ParseFlags()

	// get full tool run time
	start_time := time.Now()

	// get date
	date := time.Now().Format("01-02-2006")

	// check domains list exists, has content, and output the domains to be tested
	// the function returns a string array of the domains to be tested. the "domains" variable is set to this string array.
	domains := CheckDomainsList(arg1)
	//CheckDomainsList(arg1)
	// build directory structure for new program
	wrutils.BuildNewProgramDirectory(arg1, date, domains)

	////                    ////
	//  start of enumeration  //
	////    				////
	io.Section("Starting Subdomain Enumeration & Generating Potential Subdomains for " + arg1)
	///
	// Phase 1: subdomain generation. - generate subdomains, run amass, run subfinder, run X simultaneously.
	///

	if wrutils.SliceContainsString(tools, "sub-generator") {
		go wrtools.PotentialSubdomainGeneratorMain(domains, arg1, date, &wg, &mute)
		wg.Add(1)
	}
	if wrutils.SliceContainsString(tools, "amass") {
		go wrtools.RunAmass(arg1, date, int(atimeout), &wg)
		wg.Add(1)
	}
	if wrutils.SliceContainsString(tools, "subfinder") {
		go wrtools.RunSubfinder(arg1, date, &wg)
		wg.Add(1)
	}
	wg.Wait()

	// this function combines all the files within the date directory for the scan (./Programs/Google/01-25-23/*) into one file, and removes duplicate entries. outputs the files: "all_enumerated_subdomains_combined.txt" & "all_enumerated_subdomains_combined_unique.txt"
	wrutils.CombineFiles(tools, arg1, date)
	// this function separates "all_enumerated_subdomains_combined_unique.txt" into separate files by top-level-domain and places them into ./Programs/<program>/<date>/top-level-domain/<top-level-domain>/<top-level-domain>-subdomains.txt
	/* start1 := time.Now()
	sortedDomains := wrutils.SeparateAllSubdomainsIntoSeparateFolders(arg1, date, domains)
	time_elapsed1 := time.Now().Sub(start1)
	str := fmt.Sprintf("Separating subdomains Done! Finished in %v.", time_elapsed1)
	io.Success(str) */

	///
	// Phase 2: validate subdomains exist via bruteforcing reverse dns lookups
	///

	io.Section("Starting Reverse DNS Bruteforcing for " + arg1)
	// start clock to get runtime
	start2 := time.Now()
	// for each domain in sortedDomain (a list of domains which has redudancies removed)

	// run puredns for the domain - an instance of puredns is ran for each domain as its required for wildcard filtering.
	wrtools.RunPuredns(arg1, date, 0, wildcard)

	// get time elapsed
	time_elapsed2 := time.Now().Sub(start2)
	// print out the commands completed and the runtime
	str2 := fmt.Sprintf("Reverse DNS Bruteforcing Done! Finished in %v.", time_elapsed2)
	io.Success(str2)

	///
	// Phase 3: Run dnsgen on each puredns output, generating permutations of the valid domains
	///
	io.Section("Starting generating permutations via dnsgen for " + arg1)
	// start clock to get runtime
	start3 := time.Now()

	//run dnsgen for each puredns output
	wrtools.RunDnsgen(arg1, date)

	time_elapsed3 := time.Now().Sub(start3)
	// print out the commands completed and the runtime
	str3 := fmt.Sprintf("Permutation generation Done! Finished in %v.", time_elapsed3)
	io.Success(str3)

	///
	// Phase 4: Validate dnsgen output subdomains exist via bruteforcing reverse dns lookups
	///

	io.Section("Starting second round of reverse DNS bruteforcing against the dnsgen output for " + arg1)

	start4 := time.Now()
	// for each domain in sortedDomain (a list of domains which has redudancies removed)

	// run puredns for the domain - an instance of puredns is ran for each domain as its required for wildcard filtering.
	wrtools.RunPuredns(arg1, date, 1, wildcard)

	// get time elapsed
	time_elapsed4 := time.Now().Sub(start4)
	// print out the commands completed and the runtime
	str4 := fmt.Sprintf("Reverse DNS Bruteforcing against dnsgen ouput done! Finished in %v.", time_elapsed4)
	io.Success(str4)

	///
	// Phase 5: Completion and clean up. Combine dnsgen outputs, place into <date> directory for test. print a goodbye message
	///
	io.Section("All enumeration and reverse DNS bruteforcing complete. Creating output files for " + arg1 + "...")
	wrutils.CreateFileOfAllValidSubdomainsCombined(arg1, date)

	fullruntime_elapsed := time.Now().Sub(start_time)
	// print out the commands completed and the runtime
	str5 := fmt.Sprintf("WebRecon2 Complete! Finished in %v.", fullruntime_elapsed)
	io.Success(str5)
}
