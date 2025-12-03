#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 domain.com OR $0 domains.txt"
    exit 1
fi

input=$1

process_domain() {
    local domain=$1
    echo "[*] Running waybackurls for $domain..."
    waybackurls "$domain" | grep -Ev '\.(js|css|png|jpg|jpeg|gif|svg|woff|ico|pdf|zip|bmp|ttf|eot|otf|webp|txt)(\?|$)' >> "$temp_file"
}

if [[ -f "$input" ]]; then
    first_domain=$(head -n 1 "$input" | xargs)
    if [[ -z "$first_domain" ]]; then
        echo "[!] First domain in file is empty. Please check the file."
        exit 1
    fi

    temp_file="${first_domain}_temp.txt"
    output_file="${first_domain}.txt"
    rm -f "$temp_file" "$output_file" 2>/dev/null

    while IFS= read -r domain || [ -n "$domain" ]; do
        domain=$(echo "$domain" | xargs)
        if [[ -z "$domain" || "$domain" == \#* ]]; then
            continue
        fi
        echo "[*] Processing domain: $domain"
        process_domain "$domain"
    done < "$input"

else
    domain=$input
    temp_file="${domain}_temp.txt"
    output_file="${domain}.txt"
    rm -f "$temp_file" "$output_file" 2>/dev/null

    process_domain "$domain"
fi

echo "[*] Sorting and scanning with httpx..."
sort -u "$temp_file" | httpx -silent -o "$output_file"

rm -f "$temp_file"
echo "[+] Temp file deleted: $temp_file"
echo "[+] Done. Live URLs saved to: $output_file"
