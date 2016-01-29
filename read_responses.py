# The DNS responses are base64-encoded
import base64

# We want lines starting at the 85th, but we're using a zero-based system
lines = [i.strip() for i in open("query_responses").readlines()][84:] 

# Let's have the image data accumulate in this variable
image_data = b""

for line in lines:
    # We want to base64 decode the entire line, then take everything past the
    # 5th character ("FILE:" is 5 characters). Let's add it to the variable
    # we defined above
    image_data += base64.b64decode(line)[5:]

# Great, now all of our data is in the image_data variable. Let's write it out
# to an image so we can actually use it:

with open("image.jpg", "wb") as image_file:
    image_file.write(image_data)
