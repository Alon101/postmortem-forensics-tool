#!/bin/bash
#!/bin/bash
#########################################################################
#         ___  ____  ____________  _______  ___  ____________  ___      #
#        / _ \/ __ \/ __/_  __/  |/  / __ \/ _ \/_  __/ __/  |/  /      #
#       / ___/ /_/ /\ \  / / / /|_/ / /_/ / , _/ / / / _// /|_/ /       #
#       /_/   \____/___/ /_/ /_/  /_/\____/_/|_| /_/ /___/_/  /_/       #
#                                                                       #
#                   HDD & Memory Analysis Automation                    #
#########################################################################
#  Student  : Alon Agronov   |   Student code: s16                      #
#  Class    : TMagen773642                                              #
#  Lecturer : Natalie Erez                                              #
#########################################################################
#  Tools    : Bulk Extractor, Binwalk, Foremost, Strings, Volatility 3  #
#  Usage    : sudo ./postmortem.sh <image_file>                         #
#########################################################################

declare -A tools=(														#this mapping helps make it easier to install the tools
    [bulk_extractor]="bulk-extractor"
    [binwalk]="binwalk"
    [foremost]="foremost"
    [strings]="binutils"
)

die() { 																# helper function to print errors
	echo "$1" >&2
	exit 1
}
is_root(){																# is user root?
	(( $EUID == 0 )) || die "[*] Please start the tool with root privileges"
}

select_file(){ 															# prompt the user to enter filename
	TARGET="$1"
	if [ -z "$TARGET" ]; then
		read -p "[*] Enter file to analyze: " TARGET
	fi
	[[ -f "$TARGET" ]] || die "[*] File does not exist: $TARGET"	
}

tool_check() { 															# will loop this command whenever I need to check dependency for a tool.
	command -v "$1" >/dev/null 2>&1
}

check_dependencies() { 													# are any tools missing?
	local missing=()
	for tool in "${!tools[@]}"; do
		if ! tool_check "$tool"; then
			missing+=("${tools[$tool]}")
		fi
	done
	if (( ${#missing[@]} > 0 )); then
		echo "[*] Missing the tools: ${missing[*]} , proceeding to install them now..."
		apt-get update || die "[*] Failed to update package lists"
		apt-get install -y "${missing[@]}" || die "[*] Failed to install missing tools"
	fi
	# re-verifying
	for tool in "${!tools[@]}"; do
		tool_check "$tool" || die "[*] Failed to install: ${tools[$tool]}"
		done
	
}

new_dir() {																# creating the baseline Directory
	local filename
	local base
	
	filename=$(basename -- "$TARGET")
	base="${filename%.*}"
	
	OUTDIR="results_${base}_$(date +%F_%H%M%S)"
	
    mkdir -p \
        "$OUTDIR/bulk_extractor" \
        "$OUTDIR/foremost" \
        "$OUTDIR/binwalk" \
        "$OUTDIR/strings" \
        "$OUTDIR/volatility" \
        "$OUTDIR/report" \
        "$OUTDIR/logs" \
        || die "[*] Failed to create output directories"
}

foremost_run() {
	printf '%s\n' "-------------------------------------------"
	echo "[*] Running Foremost..."
	foremost -i "$TARGET" -o "$OUTDIR/foremost" > "$OUTDIR/logs/foremost.log" 2>&1 || die "[*] Foremost failed!"	
	echo "[*] Completed Foremost!"
	printf '%s\n' "-------------------------------------------"
}

binwalk_run() {
    local bw_status

    printf '%s\n' "-------------------------------------------"
    echo "[*] Running Binwalk..."
    
    binwalk "$TARGET" > "$OUTDIR/binwalk/signature_scan.txt" 2>&1


    binwalk -Me "$TARGET" -C "$OUTDIR/binwalk" \
        > "$OUTDIR/logs/binwalk.log" 2>&1
    bw_status=$?

    if (( bw_status != 0 )); then
        echo "[*] Binwalk completed with warnings or partial extraction issues."
        echo "[*] See: $OUTDIR/logs/binwalk.log"
    else
		echo "[*] Binwalk extracted files into: $OUTDIR/binwalk"
    fi

    echo "[*] Completed Binwalk."
    printf '%s\n' "-------------------------------------------"
}

bulk_run() {
	local be_status
	
	printf '%s\n' "-------------------------------------------"
	echo "[*] Running Bulk Extractor..."
	
	bulk_extractor -o "$OUTDIR/bulk_extractor" "$TARGET" > "$OUTDIR/logs/bulk_extractor.log" 2>&1
	
	be_status=$?
	
	if (( be_status != 0 )); then
		echo "[*] Bulk Extractor completed with warnings - see /logs/bulk_extractor.log"
	fi
	
	local pcap="$OUTDIR/bulk_extractor/packets.pcap"
	if [[ -f "$pcap" ]]; then
		local size
		size=$(du -h "$pcap" | cut -f1)
		echo "[*] Network capture ($size) carved and can be found at: $pcap"
	else
		echo "[*] No network traffic packets.pcap found."
	fi
	
	echo "[*] Completed Bulk Extractor."
	printf '%s\n' "-------------------------------------------"
	
	}
	
strings_run() {
	printf '%s\n' "-------------------------------------------"
	echo "[*] Extracting readable strings..."
	local full="$OUTDIR/strings/unfiltered_strings.txt"
	
	strings "$TARGET" > "$full" 2>/dev/null
	
	local keywords=("password" "passwd" "username" "login" "token" "\.exe" "api" "secret" "mail" "confidential")
	for kw in "${keywords[@]}"; do
		grep -in "$kw" "$full" > "$OUTDIR/strings/${kw}.txt" 2>/dev/null
		local count
		count=$(wc -l < "$OUTDIR/strings/${kw}.txt")
		echo " '$kw' - $count hits"
	done
	echo "[*] Completed strings analysis."
	printf '%s\n' "-------------------------------------------"
	}
	
detect_volatility() {													# Vol is tricky, I went for VOL3, which is less of a hassle to verify than 2
    local candidates=("vol" "vol.py" "volatility3" "volatility")
    for c in "${candidates[@]}"; do
        if tool_check "$c"; then
            VOL="$c"
            echo "[*] Found Volatility as: $VOL"
            return 0
        fi
    done
    local paths=(/home/*/.local/bin/vol /root/.local/bin/vol)
    for p in "${paths[@]}"; do
        if [[ -x "$p" ]]; then
            VOL="$p"
            echo "[*] Found Volatility at: $VOL"
            return 0
        fi
    done
    echo "[*] Volatility not found — skipping memory analysis."
    return 1
}

vol_check() {
    "$VOL" -f "$TARGET" windows.info > "$OUTDIR/volatility/info.txt" 2>&1
    if (( $? != 0 )); then
        echo "[*] Volatility 3 could not analyze this file - skipping memory analysis."
        return 1
    fi
    return 0
}
	
plugin_run() {															# running the plugins for VOL3...
    local plugin="$1" outfile="$2"
    echo "[*] Running $plugin..."
    "$VOL" -f "$TARGET" "$plugin" \
        > "$OUTDIR/volatility/$outfile" 2> "$OUTDIR/logs/vol_${outfile}.log" \
        || echo "[!] $plugin had issues"
}
	
file_count() {															# count the amount of files produced
	find "$1" -type f 2>/dev/null | wc -l
	
	}
	
generate_report() {														# final report
    local report="$OUTDIR/report/report.txt"

  
    cat > "$report" <<EOF
===========================================
      FORENSIC ANALYSIS REPORT
===========================================
Target file : $TARGET
Date        : $(date)
Runtime     : $RUNTIME seconds
Output dir  : $OUTDIR
===========================================

-- Files Extracted Per Tool --
EOF

    local total=0
    for dir in foremost binwalk bulk_extractor strings volatility; do
        local count
        count=$(file_count "$OUTDIR/$dir")
        printf "%-15s : %s files\n" "$dir" "$count" >> "$report"
        total=$((total + count))
    done
    echo "Total files : $total" >> "$report"
    
    echo "-- Strings Keyword Hits --" >> "$report"
	for f in "$OUTDIR/strings/"*.txt; do
		[[ "$f" == *unfiltered_strings.txt ]] && continue
		local name count
		name=$(basename "$f" .txt)             
		count=$(wc -l < "$f")
		printf "%-15s : %s hits\n" "$name" "$count" >> "$report"
	done
	
    echo "[*] Report saved to: $report"

	
}

zip_it_ship_it() {														# zipping everything!
	local archive="${OUTDIR}.zip"
	echo "[*] Zipping the results..."
	zip -r "$archive" "$OUTDIR" > /dev/null 2>&1 && echo "[*] Archive created: $archive" || echo "[!] Zipping failed :( "
	
	}


main() {																# pretty straight forward
		START=$(date +%s)
		is_root
		select_file "$1"
		check_dependencies
		new_dir
		foremost_run
		binwalk_run
		bulk_run
		strings_run
		
		if detect_volatility && vol_check; then							# if Volatility is found - proceed to run plugins
			plugin_run windows.pslist pslist.txt
			plugin_run windows.netstat netstat.txt
			plugin_run windows.registry.hivelist hivelist.txt
		fi
		
		for dir in foremost binwalk bulk_extractor strings volatility; do
			count=$(file_count "$OUTDIR/$dir")
			echo "$dir: $count files"
		done
		
		END=$(date +%s)
		RUNTIME=$((END - START))
		echo "Analysis took $RUNTIME seconds"
		generate_report
		zip_it_ship_it
}

main "$@"
