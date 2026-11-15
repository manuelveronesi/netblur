#!/bin/sh
# Adds netblur to the right-click menu of the file manager on macOS and Linux.
#
#   sh install-menu.sh            install
#   sh install-menu.sh --remove   remove everything this script created
#
# macOS:  two Quick Actions in Finder (right-click, Quick Actions).
# Linux:  two entries under Scripts in GNOME Files (Nautilus), Nemo and Caja,
#         and a "netblur" submenu in Dolphin (KDE).
# Run it from the folder where you keep netblur.py; that copy is the one the menu will use.

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
NAME1='netblur (secrets only)'
NAME2='netblur (secrets and personal data)'
OS=$(uname -s)

if [ "$OS" = Darwin ]; then
    DATA="$HOME/Library/Application Support/netblur"
    SERVICES="$HOME/Library/Services"
else
    SHARE="${XDG_DATA_HOME:-$HOME/.local/share}"
    CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}"
    DATA="$SHARE/netblur"
fi
LAUNCHER="$DATA/netblur-menu.sh"

remove_all() {
    rm -f "$LAUNCHER"
    rmdir "$DATA" 2>/dev/null || true
    if [ "$OS" = Darwin ]; then
        rm -rf "${SERVICES:?}/${NAME1:?}.workflow" "${SERVICES:?}/${NAME2:?}.workflow"
    else
        for dir in "$SHARE/nautilus/scripts" "$SHARE/nemo/scripts" "$CONFIG/caja/scripts"; do
            rm -f "$dir/$NAME1" "$dir/$NAME2"
        done
        rm -f "$SHARE/kio/servicemenus/netblur.desktop" "$SHARE/kservices5/ServiceMenus/netblur.desktop"
    fi
}

if [ "${1:-}" = "--remove" ]; then
    remove_all
    echo "netblur menu entries removed."
    exit 0
fi

if [ ! -f "$HERE/netblur.py" ]; then
    echo "netblur.py not found next to this script." >&2
    exit 1
fi
PYTHON=$(command -v python3 || true)
if [ -z "$PYTHON" ]; then
    echo "python3 not found. Install Python 3.9 or later, then run this script again." >&2
    exit 1
fi

# One launcher shared by every menu entry. It opens the netblur window with the report;
# without tkinter it runs in the background and opens the report as a text file.
mkdir -p "$DATA"
sh_quote() {  # single-quote a value for a shell script, apostrophes included
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}
{
    echo '#!/bin/sh'
    echo "PYTHON=$(sh_quote "$PYTHON")"
    echo "NETBLUR=$(sh_quote "$HERE/netblur.py")"
} > "$LAUNCHER"
cat >> "$LAUNCHER" <<'LAUNCHER_END'
[ "$#" -gt 0 ] || exit 0
if [ -z "${NETBLUR_MENU_NO_WINDOW:-}" ]; then
    "$PYTHON" "$NETBLUR" --gui "$@"
    [ "$?" -eq 3 ] || exit 0
fi
report=$(mktemp "${TMPDIR:-/tmp}/netblur-report.XXXXXX")
"$PYTHON" "$NETBLUR" "$@" > "$report" 2>&1
mv "$report" "$report.txt"
[ -n "${NETBLUR_MENU_NO_WINDOW:-}" ] && exit 0
if [ "$(uname -s)" = Darwin ]; then
    open -e "$report.txt"
else
    xdg-open "$report.txt" >/dev/null 2>&1 &
fi
LAUNCHER_END
chmod +x "$LAUNCHER"

xml_escape() {
    printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

quick_action() {  # name, extra option
    rm -rf "${SERVICES:?}/${1:?}.workflow"
    bundle="$SERVICES/$1.workflow/Contents"
    mkdir -p "$bundle"
    command=$(xml_escape "$(sh_quote "$LAUNCHER") $2 \"\$@\"")
    cat > "$bundle/Info.plist" <<PLIST_END
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>NSServices</key>
	<array>
		<dict>
			<key>NSMenuItem</key>
			<dict>
				<key>default</key>
				<string>$1</string>
			</dict>
			<key>NSMessage</key>
			<string>runWorkflowAsService</string>
			<key>NSRequiredContext</key>
			<dict>
				<key>NSApplicationIdentifier</key>
				<string>com.apple.finder</string>
			</dict>
			<key>NSSendFileTypes</key>
			<array>
				<string>public.item</string>
			</array>
		</dict>
	</array>
</dict>
</plist>
PLIST_END
    cat > "$bundle/document.wflow" <<WFLOW_END
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AMApplicationBuild</key>
	<string>521.1</string>
	<key>AMApplicationVersion</key>
	<string>2.10</string>
	<key>AMDocumentVersion</key>
	<string>2</string>
	<key>actions</key>
	<array>
		<dict>
			<key>action</key>
			<dict>
				<key>AMAccepts</key>
				<dict>
					<key>Container</key>
					<string>List</string>
					<key>Optional</key>
					<true/>
					<key>Types</key>
					<array>
						<string>com.apple.cocoa.string</string>
					</array>
				</dict>
				<key>AMActionVersion</key>
				<string>2.0.3</string>
				<key>AMApplication</key>
				<array>
					<string>Automator</string>
				</array>
				<key>AMParameterProperties</key>
				<dict>
					<key>COMMAND_STRING</key>
					<dict/>
					<key>CheckedForUserDefaultShell</key>
					<dict/>
					<key>inputMethod</key>
					<dict/>
					<key>shell</key>
					<dict/>
					<key>source</key>
					<dict/>
				</dict>
				<key>AMProvides</key>
				<dict>
					<key>Container</key>
					<string>List</string>
					<key>Types</key>
					<array>
						<string>com.apple.cocoa.string</string>
					</array>
				</dict>
				<key>ActionBundlePath</key>
				<string>/System/Library/Automator/Run Shell Script.action</string>
				<key>ActionName</key>
				<string>Run Shell Script</string>
				<key>ActionParameters</key>
				<dict>
					<key>COMMAND_STRING</key>
					<string>$command</string>
					<key>CheckedForUserDefaultShell</key>
					<true/>
					<key>inputMethod</key>
					<integer>1</integer>
					<key>shell</key>
					<string>/bin/sh</string>
					<key>source</key>
					<string></string>
				</dict>
				<key>BundleIdentifier</key>
				<string>com.apple.RunShellScript</string>
				<key>CFBundleVersion</key>
				<string>2.0.3</string>
				<key>CanShowSelectedItemsWhenRun</key>
				<false/>
				<key>CanShowWhenRun</key>
				<true/>
				<key>Category</key>
				<array>
					<string>AMCategoryUtilities</string>
				</array>
				<key>Class Name</key>
				<string>RunShellScriptAction</string>
				<key>InputUUID</key>
				<string>$(uuidgen)</string>
				<key>Keywords</key>
				<array>
					<string>Shell</string>
					<string>Script</string>
					<string>Command</string>
					<string>Run</string>
					<string>Unix</string>
				</array>
				<key>OutputUUID</key>
				<string>$(uuidgen)</string>
				<key>UUID</key>
				<string>$(uuidgen)</string>
				<key>UnlocalizedApplications</key>
				<array>
					<string>Automator</string>
				</array>
				<key>arguments</key>
				<dict/>
				<key>isViewVisible</key>
				<integer>1</integer>
			</dict>
			<key>isViewVisible</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>connectors</key>
	<dict/>
	<key>workflowMetaData</key>
	<dict>
		<key>serviceInputTypeIdentifier</key>
		<string>com.apple.Automator.fileSystemObject</string>
		<key>serviceOutputTypeIdentifier</key>
		<string>com.apple.Automator.nothing</string>
		<key>serviceProcessesInput</key>
		<integer>0</integer>
		<key>workflowTypeIdentifier</key>
		<string>com.apple.Automator.servicesMenu</string>
	</dict>
</dict>
</plist>
WFLOW_END
}

file_manager_scripts() {  # directory
    mkdir -p "$1"
    printf '#!/bin/sh\nexec %s "$@"\n' "$(sh_quote "$LAUNCHER")" > "$1/$NAME1"
    printf '#!/bin/sh\nexec %s --personal "$@"\n' "$(sh_quote "$LAUNCHER")" > "$1/$NAME2"
    chmod +x "$1/$NAME1" "$1/$NAME2"
}

if [ "$OS" = Darwin ]; then
    mkdir -p "$SERVICES"
    quick_action "$NAME1" ""
    quick_action "$NAME2" "--personal"
    /System/Library/CoreServices/pbs -update 2>/dev/null || true
    echo "Installed. In Finder: right-click one or more files, Quick Actions, $NAME1."
    echo "If the entries are missing, enable them in System Settings, Privacy & Security, Extensions, Finder."
else
    found=""
    if command -v nautilus >/dev/null 2>&1; then
        found="$found Nautilus"
        file_manager_scripts "$SHARE/nautilus/scripts"
    fi
    if command -v nemo >/dev/null 2>&1; then
        found="$found Nemo"
        file_manager_scripts "$SHARE/nemo/scripts"
    fi
    if command -v caja >/dev/null 2>&1; then
        found="$found Caja"
        file_manager_scripts "$CONFIG/caja/scripts"
    fi
    if command -v dolphin >/dev/null 2>&1; then
        found="$found Dolphin"
        for dir in "$SHARE/kio/servicemenus" "$SHARE/kservices5/ServiceMenus"; do
            mkdir -p "$dir"
            cat > "$dir/netblur.desktop" <<DESKTOP_END
[Desktop Entry]
Type=Service
X-KDE-ServiceTypes=KonqPopupMenu/Plugin
MimeType=all/all;
Actions=netblurSecrets;netblurPersonal;
X-KDE-Submenu=netblur

[Desktop Action netblurSecrets]
Name=$NAME1
Icon=security-high
Exec="$LAUNCHER" %F

[Desktop Action netblurPersonal]
Name=$NAME2
Icon=view-private
Exec="$LAUNCHER" --personal %F
DESKTOP_END
            chmod +x "$dir/netblur.desktop"
        done
    fi
    if [ -z "$found" ]; then
        # No known file manager on PATH: write the GNOME Files scripts anyway, they are harmless.
        file_manager_scripts "$SHARE/nautilus/scripts"
        echo "No supported file manager found on PATH. Scripts written for GNOME Files in case it is installed later."
    else
        echo "Installed for:$found."
    fi
    echo "GNOME Files, Nemo, Caja: right-click one or more files, Scripts, $NAME1."
    echo "Dolphin: right-click, netblur."
    "$PYTHON" -c "import tkinter" 2>/dev/null || echo "Tip: install python3-tk to get the netblur window. Without it the report opens as a text file."
fi
echo "The menu uses: $HERE/netblur.py"
