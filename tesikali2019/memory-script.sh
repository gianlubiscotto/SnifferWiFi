echo $(date '+%a %d %b %Y %T') $(free | grep Mem | awk '{print ($3+$5+$6)/$2 * 100.0}')% >> memory-log.txt

