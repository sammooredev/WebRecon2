package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/sammooredev/WebRecon/wrtools"
	"github.com/sammooredev/WebRecon/wrutils"

	"github.com/DrSmithFr/go-console/pkg/input"
	"github.com/DrSmithFr/go-console/pkg/output"
	"github.com/DrSmithFr/go-console/pkg/style"
)

///
// Subdomain Enumeration Functions
///

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
	io.Title("WebRecon - subdomain enooooooooomeration")

	// check user inputted an argument (./WebRecon arguement). if not, print help & exit, else continue
	wrutils.CheckUserInput()

	// get full tool run time
	full_runtime := time.Now()
	// get program name as argument
	arg1 = os.Args[1]

	// get date
	date := time.Now().Format("01-02-2006")

	// check domains list exists, has content, and output the domains to be tested
	// the function returns a string array of the domains to be tested. the "domains" variable is set to this string array.
	domains := wrutils.CheckDomainsList(arg1)
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

	go wrtools.PotentialSubdomainGeneratorMain(domains, arg1, date, &wg, &mute)
	wg.Add(1)
	go wrtools.RunAmass(arg1, date, 1, &wg)
	wg.Add(1)
	go wrtools.RunSubfinder(arg1, date, &wg)
	wg.Add(1)
	wg.Wait()

	// this function combines all the files within the date directory for the scan (./Programs/Google/01-25-23/*) into one file, and removes duplicate entries. outputs the files: "all_enumerated_subdomains_combined.txt" & "all_enumerated_subdomains_combined_unique.txt"
	wrutils.CombineFiles(arg1, date)
	// this function separates "all_enumerated_subdomains_combined_unique.txt" into separate files by top-level-domain and places them into ./Programs/<program>/<date>/top-level-domain/<top-level-domain>/<top-level-domain>-subdomains.txt
	start1 := time.Now()
	sortedDomains := wrutils.SeparateAllSubdomainsIntoSeparateFolders(arg1, date, domains)
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
		// run puredns for the domain - an instance of puredns is ran for each domain as its required for wildcard filtering.
		go wrtools.RunPuredns(arg1, date, domain, 0, &wg)
		wg.Add(1)
	}
	wg.Wait()
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
	for _, domain := range sortedDomains {
		//run dnsgen for each puredns output
		go wrtools.RunDnsgen(arg1, date, domain, &wg)
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

	io.Section("Starting second round of reverse DNS bruteforcing against the dnsgen output for " + arg1)

	start4 := time.Now()
	// for each domain in sortedDomain (a list of domains which has redudancies removed)
	for _, domain := range sortedDomains {
		// run puredns for the domain - an instance of puredns is ran for each domain as its required for wildcard filtering.
		go wrtools.RunPuredns(arg1, date, domain, 1, &wg)
		wg.Add(1)
	}
	wg.Wait()
	// get time elapsed
	time_elapsed4 := time.Now().Sub(start4)
	// print out the commands completed and the runtime
	str4 := fmt.Sprintf("Reverse DNS Bruteforcing against dnsgen ouput done! Finished in %v.", time_elapsed4)
	io.Success(str4)

	///
	// Phase 5: Completion and clean up. Combine dnsgen outputs, place into <date> directory for test. print a goodbye message
	///
	io.Section("All enumeration and reverse DNS bruteforcing complete. Creating output files for " + arg1 + "...")
	wrutils.CreateFileOfAllValidSubdomainsCombined(arg1, date, sortedDomains)

	fullruntime_elapsed := time.Now().Sub(full_runtime)
	// print out the commands completed and the runtime
	str5 := fmt.Sprintf("WebRecon2 Complete! Finished in %v.", fullruntime_elapsed)
	io.Success(str5)
}
