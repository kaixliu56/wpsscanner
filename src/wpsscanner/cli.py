from wpsscanner.path_detector import *

disable_warnings()


class Information:
    def __init__(self, thread, web_path, recursion_flag, output):
        self.thread = thread
        self.web_path = web_path
        self.recursion_flag = recursion_flag
        self.save_filename = output
        self.valid_paths = []

    def print_info(self):
        print("[*] information:")
        print(f"[*] thread num: {self.thread}")
        print(f"[*] is recursive scanning: {self.recursion_flag}")
        print(f"[*] output file: ./{self.save_filename}")

    def get_results(self, valid_paths):
        self.valid_paths += valid_paths

    def output_results(self):
        print("\n[*] valid paths:")
        if self.save_filename:
            with open(self.save_filename, "w", encoding="utf-8") as f:
                if self.valid_paths:
                    for path in self.valid_paths:
                        f.write(path + "\n")
                        print(path)
            print(f"\n[*] result has been written to ./{self.save_filename}")
        else:
            if self.valid_paths:
                for path in self.valid_paths:
                    print(path)


def single_target_scan(target, infos):
    detector = PathDetector(target)
    print(f"\n[*] Start scanning the target: {target}")
    result = detector.run(thread_num=infos.thread, webpaths=infos.web_path)
    valid_paths = result[0]
    recursion_paths = result[1]
    if infos.recursion_flag:
        if recursion_paths:
            for new_target in recursion_paths:
                print(f"\n[*] Recursive scanning: {new_target}")
                d = PathDetector(new_target)
                valid_paths += d.run(thread_num=infos.thread, webpaths=infos.web_path)[0]
        infos.get_results(valid_paths=valid_paths)
    else:
        infos.get_results(valid_paths=valid_paths)


def main():
    logo()
    parser = argparse.ArgumentParser(description='Web path scanning tool')
    parser.add_argument('-u', '--target', help='[*] Target URL')
    parser.add_argument('-l', '--list', help='[*] File containing target URLs')
    parser.add_argument('-w', '--wordlist', help='[*] Wordlist file')
    parser.add_argument(
        '-t', '--thread',
        type=int,
        default=40,
        help='[*] Number of threads (default: 40)'
    )
    parser.add_argument(
        '-r', '--recursion',
        action='store_true',
        default=False,
        help='[*] Enable recursive scanning (only one level supported)'
    )
    parser.add_argument(
        '-o', '--output',
        help='[*] Output results to a file'
    )

    args = parser.parse_args()
    # Parse all arguments

    # Validate arguments
    if (args.target and args.list) or (not args.target and not args.list) or not args.wordlist:
        print("[*] Invalid arguments! Use -h or --help for usage.")
        print(f"[*] Usage: python {sys.argv[0]} -u http://www.example.com -w web_path.txt -t 10")
        print(f"[*]        python {sys.argv[0]} -l targets.txt -w web_path.txt -t 10")
        sys.exit(0)

    if not os.path.exists(args.wordlist):
        print("[*] Wordlist file does not exist!")
        sys.exit(1)

    with open(args.wordlist, "r", encoding="utf-8") as f:
        web_paths = [path.strip() for path in f.readlines()]

    infos = Information(
        thread=args.thread,
        web_path=web_paths,
        recursion_flag=args.recursion,
        output=args.output
    )
    infos.print_info()

    if args.target:
        target = args.target.strip("/") + "/"
        single_target_scan(target, infos)

    if args.list:
        if not os.path.exists(args.list):
            print("[*] Target list file does not exist!")
            sys.exit(1)

        with open(args.list, "r", encoding="utf-8") as f:
            urls = [url.strip() for url in f.readlines()]

        for url in tqdm(urls, desc="All tasks progress:", total=len(urls), leave=False, position=1):
            target = url.strip("/") + "/"
            single_target_scan(target, infos)

    infos.output_results()


if __name__ == "__main__":
    main()
