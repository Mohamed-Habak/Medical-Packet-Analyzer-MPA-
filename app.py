# This Flask application was designed and implemented by Mohamed Habak.
# ChatGPT was used as a learning and guidance tool during development.
# Some code structure outlines (function skeletons, route templates) and several
# explanatory comments were drafted or refined with ChatGPT’s assistance.
# All final logic, implementation, debugging, and functionality verification were done by me.


import os                        # For interacting with the operating system: creating folders, joining file paths, checking if files exist, etc.
import json                      # For reading from and writing to JSON files; converts Python objects (like dicts) to JSON strings and vice versa.
from flask import Flask, render_template, request, redirect, url_for, flash
                                 # Flask: a micro web framework for building web applications.
                                 # Flask components:
                                 # - Flask: main class to create the web app.
                                 # - render_template: renders HTML templates and passes data to them.
                                 # - request: handles incoming HTTP requests and data (like uploaded files or form data).
                                 # - redirect: sends the user to a different route.
                                 # - url_for: generates URLs dynamically based on route names.
                                 # - flash: shows temporary messages to users (e.g., success/error messages).
from werkzeug.utils import secure_filename
                                 # Werkzeug is a utility library Flask depends on.
                                 # secure_filename(): sanitizes uploaded filenames to prevent security issues
from analyzer.pcap_parser import parse_pcap  # import my custom parse_pcap function

UPLOAD_DIRECTORY = "uploads"  # folder to save uploads
ALLOWED_EXT = {".pcap", ".pcapng"}  # allowed file types
os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)  # create the uploads folder if it doesn't exist

app = Flask(__name__)
app.secret_key = os.urandom(24)  # This generates a random key that Flask uses to sign cookies and keep track of information like flash messages.
                                 # It’s similar to the default session setup used in CS50 problem sets like "Finance," which handles this automatically in the background.
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200 MB upload limit

# === Helper Function ===
def allowed_file(filename):
    """Check if uploaded file has an allowed extension."""  # these are docstrings that explain what each function does.
    # Extract the file extension and verify it is an allowed type
    prefix, suffix = os.path.splitext(filename)
    if suffix.lower() in ALLOWED_EXT:
        return True
    else:
        return False

# === Route: Home Page ===
@app.route("/")
def index():
    """Display upload form."""
    # Render the index.html page for uploading PCAP files
    return render_template("index.html")


# === Route: Handle Upload ===
@app.route("/upload", methods=["POST"])
def upload():
    """Handle PCAP file upload and analysis."""

    # Retrieve the uploaded file from the request object
    file = request.files.get("pcap") # this means that 'file' is now a Flask FileStorage object that represents the uploaded file. not the raw file data.
    

    # Validate that a file was provided
    if not file:
        flash("No file uploaded", "danger") # "danger" is a bootstrap class that makes the flash message red.
        return redirect(url_for("index"))# i used redirect(url_for("index")) instead of render_template("index.html") because redirecting is a better practice after a POST request to avoid form resubmission issues.
                                         # i also made the path dynamic by using url_for("index") instead of hardcoding "/" in case i decide to change the route for one reason or another.
    

    # Sanitize the filename for safe storage
    cleaned_filename = secure_filename(file.filename)  # secure_filename() is a helper function from Flask’s Werkzeug library that cleans the filename attribute of the file object (not the file itself). for example "my pcap.pcap" becomes "my_pcap.pcap" or ""../../../etc/passwd" becomes "etc_passwd"
                                                       # NOTE: .filename is an attribute of the FileStorage object that contains the original name of the uploaded file. for example, if the user uploaded a file named "my pcap.pcap", then file.filename would be "my pcap.pcap".


    # Check that the uploaded file has a valid extension
    if not allowed_file(cleaned_filename):
        flash("Unsupported file type. Please upload a .pcap or .pcapng file.", "danger")
        return redirect(url_for("index"))


    # Save the uploaded file to the designated uploads folder
    path = os.path.join(UPLOAD_DIRECTORY, cleaned_filename) # this creates a full path to where the file will be saved, it merges the upload directory and the cleaned filename like so: "uploads" + "/" + "my_pcap.pcap" = "uploads/my_pcap.pcap"
    file.save(path)  # this creates/saves the file on disk at the specified path


    # Analyze the saved PCAP file using parse_pcap()
    # Handle any exceptions during parsing
    try:
        summary = parse_pcap(path)  # this calls the parse_pcap() function from analyzer/pcap_parser.py, passing in the path to the saved file. It returns a summary dictionary containing analysis results.
        if summary is None:
            flash("Failed to parse PCAP file.", "danger")
            return redirect(url_for("index"))
    except Exception as e:
        flash(f"Error parsing PCAP file: {e}", "danger")
        return redirect(url_for("index")) 
    

    # Save the analysis summary as a JSON file for later use
    summary["filename"] = cleaned_filename  # adds the filename to the summary dictionary for the sake of data completeness and to render it on the dashboard page later on.
    summary_path = os.path.join(UPLOAD_DIRECTORY, cleaned_filename + ".json") # this creates a path for the summary JSON file by appending ".json" to the cleaned filename
                                                                              # for example, if cleaned_filename is "my_pcap.pcap", then summary_path will be "uploads/my_pcap.pcap.json". even though it looks weird, it isn't going to break any logic for now.
    try:
        with open(summary_path, "w", encoding="utf-8") as f: # encoding="utf-8" is just incase the summary dictionary contains some wierd charcters that aren't ASCII. 
            json.dump(summary, f, default=str) # this takes the "summary" results from my parse_pcap() function (which is a Python dictionary) and turns it into a JSON string and writes it to the file at summary_path
                                  # this json file was created so that I can load it later when viewing individual packets without having to re-parse the original pcap file again.
                                  # default=str is there to change objects that json doesn't normally support (like datetime objects) into strings, because summary contains datetime objects.
    except Exception as e:
        flash(f"Error saving summary JSON: {e}", "danger")
        return redirect(url_for("index"))


    # Render the dashboard page with analysis results
    return render_template("dashboard.html", summary=summary)


# === Route: View One Packet ===
@app.route("/packet/<filename>/<int:packet_id>") # instead of using a static route like "/" or "/upload", due to the dynamic nature of this route, I used route parameters <filename> and <int:packet_id> to capture the specific pcap file and packet ID that the user wants to view.
                                                 # meaning, when the user clicks on a link to view a specific packet, the front end of that link will look something like this: <a href=/packet/{{ filename }}/{{ packet.id }}"> and Flask will automatically pass those values to the view function as arguments.
                                                 # the <int:> part is to make sure that packet_id is always an integer.
def packet_view(filename, packet_id):
    """Display one specific packet’s details."""

    # Load the JSON summary file for the requested PCAP
    summary_path = os.path.join(UPLOAD_DIRECTORY, filename + ".json")
    if not os.path.exists(summary_path):
        flash("Summary file not found.", "danger")
        return redirect(url_for("index"))
        
    try:
        with open(summary_path, "r", encoding="utf-8") as f:
            summary = json.load(f)
    except Exception as e:
        flash(f"Error loading summary JSON: {e}", "danger")
        return redirect(url_for("index"))
    

    # Locate the packet with the matching ID
    selected_packet = None
    for packet in summary.get("packets", []): # i used .get("packets", []) instead of summary["packets"] just incase the "packets" key doesn't exist due to some error in parsing or some sort of crash.
                                              # using .get("packets", []) will return an empty list if the "packets" key doesn't exist.
        if packet.get("id") == packet_id:  # i used .get("id") for the same reason as above.  
            selected_packet = packet
            break
    if selected_packet is None:
        flash("Packet not found.", "danger")
        return redirect(url_for("dashboard", filename=filename))
    
    alert_for_packet = None
    for alert in summary.get("alerts", []):
        if alert.get("packet_id") == packet_id:
            alert_for_packet = alert
            break

    # Render packet.html with the selected packet's details
    return render_template("packet.html", packet=selected_packet, filename=filename, alert=alert_for_packet,)


# === Entry Point ===
if __name__ == "__main__":
    app.run(debug=True, port=5000)
