package wrtools

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sammooredev/WebRecon/wrutils"

	"github.com/DrSmithFr/go-console/pkg/input"
	"github.com/DrSmithFr/go-console/pkg/output"
	"github.com/DrSmithFr/go-console/pkg/style"
)

// TODO: rethink data structures
// function to generate potential subdomains using a list of publicly sourced subdomain names
func PotentialSubdomainGeneratorMain(domains []string, program string, date string, wg *sync.WaitGroup, mute *sync.Mutex) {
	// cmd output styling
	in := input.NewArgvInput(nil)
	out := output.NewConsoleOutput(true, nil)
	io := style.NewGoStyler(in, out)
	wordlist_array := wrutils.WordlistToArray("./wordlists/httparchive_subdomains_2022_12_28.txt")

	// split wordlist_line string array into multiple slices
	divided := wrutils.Wordlist2DArrayGenerator(wordlist_array, 20)

	// start generation
	out.Writeln("\t<info>INFO - Generating potential subdomains from file ./wordlists/httparchive_subdomains_2022_12_28.txt</info>")
	start := time.Now()
	programPath := "./Programs/" + program + "/" + date + "/sub-generator.out"
	total_generated := SubdomainGenerator(domains, divided, programPath, wg, out, mute)
	time_elapsed := time.Now().Sub(start)
	str := fmt.Sprintf("Generating potential subdomains complete! Finished in %v, generating %d subdomains.", time_elapsed, total_generated)
	io.Success(str)
	wg.Done()
}

// performs grunt work for PotentialSubdomainGeneratorMain, taking in domains, path, and 2d wordlist array,
func SubdomainGenerator(domains []string, wordlist_2d_array [][]string, path string, wg *sync.WaitGroup, out *output.ConsoleOutput, mute *sync.Mutex) int {
	// subdomains_generated_count = count total number of subdomains generated, threads_count = number of threads generated.
	var subdomains_generated_count int
	subdomains_generated_count = 0
	// start go routine waitgroup
	var wg2 sync.WaitGroup
	//create a worker for each domain in domains.txt
	//wg2.Add(len(domains))
	// Lock writing
	mute.Lock()
	defer mute.Unlock()

	//create output file
	output_file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
				defer wg2.Done()
				for _, line := range foo {
					subdomains_generated_count += 1

					output_file.WriteString(line + "." + domain + "\n")
				}
			}(domain)
		}
	}
	wg2.Wait()

	return subdomains_generated_count
}

// function to run amass.
func RunAmass(program_name string, date string, timeout int, wg *sync.WaitGroup) {
	in := input.NewArgvInput(nil)
	out := output.NewConsoleOutput(true, nil)
	io := style.NewGoStyler(in, out)
	out.Writeln("\t<info>INFO - Executing Amass against " + program_name + "</info>")

	cmd := exec.Command("bash", "-c", "amass enum -timeout "+strconv.Itoa(timeout)+" -df ./Programs/"+program_name+"/recon-data/domains.txt -o ./Programs/"+program_name+"/"+date+"/amass.out")
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
			if count == 1 {
				out.Writeln("\t<info>INFO - Amass identified first subdomain for " + program_name + " successfully.</info>")
			}
			// UNCOMMENT NEXT LINE TO DEBUG AMASS
			//log.Printf(strconv.Itoa(count) + " amass out: %s", scanner.Text())
		}
		wg2.Done()
	}()

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

	start := time.Now()
	cmd := exec.Command("bash", "-c", "subfinder -dL ./Programs/"+program_name+"/recon-data/domains.txt -o ./Programs/"+program_name+"/"+date+"/subfinder.out")
	stdout, err := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err != nil {
		log.Fatal(err)
	}

	var wg2 sync.WaitGroup
	wg2.Add(1)

	count := 0
	scanner := bufio.NewScanner(stdout)
	scanner2 := bufio.NewScanner(stderr)
	go func() {
		for scanner.Scan() {
			count += 1
			//log.Printf(strconv.Itoa(count) + " subfinder out: %s", scanner.Text())
		}
		wg2.Done()
	}()

	if err = cmd.Start(); err != nil {
		log.Fatal(err)
		log.Printf(scanner2.Text())
	}

	wg2.Wait()
	cmd.Wait() //bug where this also prints 0

	time_elapsed := time.Now().Sub(start)
	io.Success("Subfinder Enumeration Complete! Finished in " + time_elapsed.String() + ", enumerating " + strconv.Itoa(count) + " subdomains.")
	wg.Done()
}

// Bruteforce reverse DNS resolving
func RunPuredns(program_name string, date string, domain string, mode int, wildcard bool, wg *sync.WaitGroup) {
	out := output.NewConsoleOutput(true, nil)
	out.Writeln("\t<info>INFO - Executing puredns against " + domain + "</info>")

	program_path := "./Programs/" + program_name + "/" + date + "/top-level-domains/" + domain + "/"

	// get wildcard flag
	wildflag := "--wildcard-batch 1500000"
	if !wildcard {
		wildflag = "--skip-wildcard-filter"
	}

	//select mode (changes cmd command value dependenant on mode value passed as arguement. 0 = run against enumerated, 1 = run against dnsgen output)
	var cmd *exec.Cmd
	var output_file *os.File
	if mode == 0 {
		//out.Writeln("puredns -t 50000 -r ./wordlists/resolvers.txt -d " + domain + " -list " + program_path + domain + "-subdomains.out")
		//cmd = exec.Command("bash", "-c", "puredns -t 50000 -r ./wordlists/resolvers.txt -d " + domain + " -list " + program_path + domain + "-subdomains.out")// -o " + program_path + domain + "-puredns.out")
		//puredns testing
		//out.Writeln("puredns resolve " + program_path + domain + "-puredns.out -r ./wordlists/resolvers.txt")
		cmd = exec.Command("bash", "-c", "puredns resolve "+program_path+domain+"-subdomains.out --rate-limit-trusted 1000 "+wildflag+" -r ./wordlists/resolvers.txt")
		//create output file
		output_file, _ = os.OpenFile(program_path+domain+"-puredns.out", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	} else {
		//out.Writeln("puredns -t 50000 -r ./wordlists/resolvers.txt -d " + domain + " -list " + program_path + domain + "-dnsgen.out")
		//cmd = exec.Command("bash", "-c", "puredns -t 50000 -r ./wordlists/resolvers.txt -d " + domain + " -list " + program_path + domain + "-dnsgen.out")// + program_path + domain + "-dnsgen-puredns.out")
		//puredns testing
		//out.Writeln("puredns resolve " + program_path + domain + "-dnsgen.out -r ./wordlists/resolvers.txt")
		cmd = exec.Command("bash", "-c", "puredns resolve "+program_path+domain+"-dnsgen.out --rate-limit-trusted 1000 "+wildflag+" -r ./wordlists/resolvers.txt")
		output_file, _ = os.OpenFile(program_path+domain+"-dnsgen-puredns.out", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}

	stdout, _ := cmd.StdoutPipe()

	var wg2 sync.WaitGroup
	wg2.Add(1)

	var purednsout []string
	count := 0
	scanner := bufio.NewScanner(stdout)
	go func() {
		for scanner.Scan() {
			count += 1
			//log.Printf(strconv.Itoa(count) + " puredns out: %s", scanner.Text())
			purednsout = append(purednsout, strings.ToLower(scanner.Text())+"\n")
		}
		wg2.Done()
	}()

	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}

	wg2.Wait()
	cmd.Wait() //bug where this also prints 0
	for _, line := range purednsout {
		output_file.WriteString(line)
	}
	out.Writeln("\t<info>INFO - Puredns Complete for " + domain + ". Found " + strconv.Itoa(count) + " valid subdomains. </info>")
	wg.Done()
}

// Generates permutations of validated subdomains from puredns output
func RunDnsgen(program_name string, date string, domain string, wg *sync.WaitGroup) {
	out := output.NewConsoleOutput(true, nil)
	out.Writeln("\t<info>INFO - Executing dnsgen against " + domain + "</info>")

	program_path := "./Programs/" + program_name + "/" + date + "/top-level-domains/" + domain + "/"
	cmd := exec.Command("bash", "-c", "dnsgen "+program_path+domain+"-puredns.out | tee -a "+program_path+domain+"-dnsgen.out")

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
	}()

	if err = cmd.Start(); err != nil {
		log.Fatal(err)
	}

	wg2.Wait()
	cmd.Wait() //bug where this also prints 0
	out.Writeln("\t<info>INFO - dnsgen Complete for " + domain + ". Generated " + strconv.Itoa(count) + " potential subdomains. </info>")
	wg.Done()
}
