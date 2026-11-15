#!/bin/bash
# Steuert die Windows-VM im Docker-Container kx-win ueber den QEMU-Monitor.
#
# Der Monitor nimmt Tastatureingaben entgegen (`sendkey`) und macht
# Bildschirmabzuege (`screendump`). Beides laeuft ueber einen Unix-Socket im
# Container — von aussen nicht erreichbar, deshalb laeuft dieses Skript
# dort.
#
# Zwei Stolperfallen, die beide Zeit gekostet haben:
#
#  1. Die Tasten gehen verloren, wenn sie zu schnell kommen. Der Gast
#     verarbeitet die PS/2-Warteschlange langsamer, als der Monitor sendet.
#     Deshalb pauseiert der Monitor zwischen zwei Tasten — 300 ms haben
#     gereicht, 150 ms nicht.
#  2. QEMU-Keycodes sind nicht Tasten. Ein Doppelpunkt ist `shift-semicolon`,
#     ein GROSSbuchstabe `shift-buchstabe`, ein Schraegstrich `slash`. Ein
#     `sendkey D` sendet kein "D", sondern gar nichts Brauchbares.
#
# Aufruf (im Container):
#   kx-vm-control.sh tippen "n e t spc u s e"     # eine Taste nach der anderen
#   kx-vm-control.sh text  "net use z:"          # Text, Zeichen fuer Zeichen
#   kx-vm-control.sh enter                        # Enter
#   kx-vm-control.sh shot /pfad.ppm               # Bildschirmabzug
#
# Zeichen, die QEMU nicht so benennt:
#   " -> shift-apostrophe      | -> shift-backslash
#   : -> shift-semicolon        _ -> shift-minus
#   ? -> shift-slash            @ -> shift-2

MONITOR=/run/shm/monitor.sock
PAUSE=0.3

sendkey() {
    # `-q 0`: nc schliesst die Verbindung, sobald die Zeile raus ist. Ohne das
    # wartet nc noch eine Sekunde — und der Monitor nimmt nur eine Verbindung
    # gleichzeitig, die naechste Taste ginge dann ins Leere.
    printf 'sendkey %s\n' "$1" | timeout 5 nc -q 0 -U "$MONITOR" >/dev/null 2>&1
    sleep "$PAUSE"
}

# Mehrere Tasten, jede ueber eine eigene Verbindung.
#
# Der Monitor-Socket nimmt nur eine Verbindung gleichzeitig; deshalb muss jede
# Verbindung sofort wieder zu. Eine gemeinsame Verbindung waere schneller,
# aber `nc` puffert die Zeilen und schickt sie erst am Ende — dann laeuft der
# Gast die Tasten ohne Pause ab und verliert welche.
sendkeys() {
    for k in "$@"; do
        sendkey "$k"
    done
}

# Alle Zeichen eines Textes in QEMU-Keycodes uebersetzen.
to_keycodes() {
    local text="$1" i ch out=()
    for (( i=0; i<${#text}; i++ )); do
        ch="${text:$i:1}"
        case "$ch" in
            " ") out+=("spc") ;;
            "-") out+=("minus") ;;
            ".") out+=("dot") ;;
            "/") out+=("slash") ;;
            ":") out+=("shift-semicolon") ;;
            ";") out+=("semicolon") ;;
            "_") out+=("shift-minus") ;;
            "=") out+=("equal") ;;
            ",") out+=("comma") ;;
            "\"") out+=("shift-apostrophe") ;;
            "'") out+=("apostrophe") ;;
            "|") out+=("shift-backslash") ;;
            "\\") out+=("backslash") ;;
            "?") out+=("shift-slash") ;;
            "$") out+=("shift-4") ;;
            "&") out+=("shift-7") ;;
            "#") out+=("shift-3") ;;
            "@") out+=("shift-2") ;;
            "€") out+=("alt-e") ;;
            [a-z]) out+=("$ch") ;;
            [A-Z]) out+=("shift-${ch,,}") ;;
            [0-9]) out+=("$ch") ;;
            *) echo "unbekanntes Zeichen: $ch" >&2; return 1 ;;
        esac
    done
    # Eine Zeile je Keycode: mapfile liest Zeilen, nicht Woerter.
    printf '%s\n' "${out[@]}"
}

# Selbsttest: prueft, dass die Uebersetzung kein Zeichen verliert.
#
# Ein unbekanntes Zeichen hat diese Funktion frueher stillschweigend
# verschluckt — der Text kam dann unvollstaendig in der VM an.
selbsttest() {
    local beispiel='powershell -c "iwr http://192.168.190.87:8090/setup.ps1 -useb | iex"'
    local codes
    codes=$(to_keycodes "$beispiel")
    local anzahl
    anzahl=$(printf '%s\n' "$codes" | grep -c .)
    local erwartet
    erwartet=${#beispiel}
    if [ "$anzahl" -ne "$erwartet" ]; then
        echo "FEHLER: $anzahl Keycodes fuer $erwartet Zeichen" >&2
        return 1
    fi
    echo "ok: $anzahl Keycodes fuer $erwartet Zeichen"
}

case "${1:-}" in
    selbsttest)
        selbsttest
        ;;
    tippen)
        # Jedes Argument ist eine Taste: "n e t spc u s e"
        sendkeys $2
        ;;
    text)
        mapfile -t codes < <(to_keycodes "$2")
        sendkeys "${codes[@]}"
        ;;
    enter)
        sendkey ret
        ;;
    shot)
        printf 'screendump %s\n' "$2" | timeout 10 nc -q 1 -U "$MONITOR" >/dev/null 2>&1
        ;;
    *)
        echo "Aufruf: $0 {selbsttest|tippen <tasten>|text <string>|enter|shot <pfad>}" >&2
        exit 2
        ;;
esac
