const {Cc, Ci} = require("chrome");
var clipboard = require("sdk/clipboard");
var data = require("sdk/self").data;

// Create a button
require("sdk/ui/button/action").ActionButton({
    id: "get-pass",
    label: "Get password for this domain.",
    icon: {
        "16": "./icon-16.png",
        "32": "./icon-32.png",
        "64": "./icon-64.png"
    },
    onClick: handleClick
});

// Show the panel when the user clicks the button.
function handleClick(state) {
    // you need to use this service first
    var windowsService = Cc['@mozilla.org/appshell/window-mediator;1'].getService(Ci.nsIWindowMediator);

    // window object representing the most recent (active) instance of Firefox
    var currentWindow = windowsService.getMostRecentWindow('navigator:browser');

    // most recent (active) browser object - that's the document frame inside the chrome
    var browser = currentWindow.getBrowser();

    // object containing all the data about an address displayed in the browser
    var uri = browser.currentURI;

    // textual representation of the actual full URL displayed in the browser
    var url = uri.spec;

    clipboard.set(url);
    console.log(url);

    var process = Cc["@mozilla.org/process/util;1"]
              .createInstance(Ci.nsIProcess);
    var file = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);

    // This makes a unreasonable assumption that the executable is always in the
    // same place.
    file.initWithPath("/home/kaan/programming/c/pastor/pastor");
    process.init(file);
    var parameters = ["-p", "asd", "/home/kaan/programming/c/pastor/database.db", url];
    process.run(true, parameters, parameters.length);
}
