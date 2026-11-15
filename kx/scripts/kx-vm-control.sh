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
    printf 'sendkey %s\n' "$1" | timeout 5 nc -q 1 -U "$MONITOR" >/dev/null 2>&1
    sleep "$PAUSE"
}

# Mehrere Tasten ueber EINE Verbindung.
#
# Der Monitor-Socket nimmt nur eine Verbindung gleichzeitig. Ruft man fuer jede
# Taste ein eigenes `nc` auf, blockiert das naechste, sobald das vorherige
# nicht sauber beendet wird — und der Rest der Tasten geht verloren. Deshalb
# gehen alle Tasten durch eine Verbindung, mit Pause zwischen den Kommandos.
sendkeys() {
    {
        for k in "$@"; do
            printf 'sendkey %s\n' "$k"
            sleep "$PAUSE"
        done
    } | timeout 120 nc -q 1 -U "$MONITOR" >/dev/null 2>&1
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
            *) echo "unbekanntes Zeichen: $ch" >&2; return 1 ;;
        esac
    done
    # Eine Zeile je Keycode: mapfile liest Zeilen, nicht Woerter.
    printf '%s\n' "${out[@]}"
}

case "${1:-}" in
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
        echo "Aufruf: $0 {tippen <tasten>|text <string>|enter|shot <pfad>}" >&2
        exit 2
        ;;
esac
