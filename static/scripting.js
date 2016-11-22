<!--

function display_error(display_msg) {
    error_obj = document.getElementById("error_display");
    error_obj.innerHTML = "<BR>Error: " + display_msg;
    error_obj.className = "error_show";
}

function validate_add_entry(){

  if (document.getElementById("encrypt").checked) {
    if (document.getElementById("ds").value != "") {
      display_error("If entering encrypted data, the encrypt checkbox must be unchecked.");
      return false;
    }
  } 

  if (document.getElementById("entry").value == "") {
    display_error("Please enter a message to send.");
    return false;
  }

  if (document.getElementById("to").value == "") {
    display_error("Please enter a valid recipient.");
    return false;
  }
}

-->
