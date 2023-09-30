# CSA_S3_2023
# CTF Writeups
## Writeups for the way I went about solving the challenges.

### Answer The Ultimate Question Of Life
Description - The following code snippet is a complex Python program that uses recursion for a given number. Your task is to analyse the code and identify the output:
```
def recursive_sum(n):
    if n <= 1:
        return n
    else:
        return n + recursive_sum(n-1)

input_num = 7
output_sum = recursive_sum(input_num)
print(output_sum)
```
Plugged this straight into ChatGPT:
```
The code you've provided defines a recursive function called recursive_sum that calculates the sum of all positive integers from 1 to a given number n. Then, it uses this function to calculate the sum of integers from 1 to 7 and prints the result.

Here's how the code works step by step for input_num = 7:

    The recursive_sum function is called with n = 7.
    Since 7 is greater than 1, the else block is executed.
    The function returns 7 + recursive_sum(6).

Now, the function calls itself with n = 6:

    Since 6 is also greater than 1, the else block is executed.
    The function returns 6 + recursive_sum(5).

This process continues until the base case is reached, which is when n becomes 1. At that point, the function returns 1 without making any further recursive calls.

So, let's sum up the calls made:
recursive_sum(7)
=> 7 + recursive_sum(6)
   => 6 + recursive_sum(5)
      => 5 + recursive_sum(4)
         => 4 + recursive_sum(3)
            => 3 + recursive_sum(2)
               => 2 + recursive_sum(1)
                  => 1 (base case)

Now, the values are "unrolled" and added up:
1 + 2 + 3 + 4 + 5 + 6 + 7 = 28

So, when you run the code with input_num = 7, it will print 28, which is the sum of integers from 1 to 7.
```
:+1: FLAG{28}
<hr>

### Backup Website
Description - Recently I had to backup my website database in case it got hacked. "Best practise" or something. 
I can't help but think if someone gets their hands on the backup they can break my actual website.

URL port: 5000

Flag format: FLAG{random_flag_f0r_this_website}

Extracting the zip reveals a tarball archive

Extracting that gives the complete backups

Search through each folder looking for juicyness

I found db.sqlite3 in the folder starting 32e6d.

Opening that in notepad reveals to accounts and hashed passwords

taking the hash for admin - 5beb1b83d944d0f81b08704490f029e083e49b6159b12eb6fcbedef359939fdf

and putting in crackstation.net, it reveals the result as fericita pana la ultima suvitza

Going to the website for the challenge - http://platf-loadb-lds4m4cnqtwz-e7e9345ee4d3f184.elb.ap-southeast-2.amazonaws.com:5000

and using admin/fericita pana la ultima suvitza the flag is revealed

:+1: FLAG{treasure_is_f0und_in_backups}
<hr>

### Crossing the multiversal plane
Description - Can you find any secrets by going Back To The future?

We were given the image [McFly.png](https://github.com/gnarkill78/CSA_S3_2023/blob/main/McFly.png)

Using aperisolve - zsteg reveals the flag

:+1: FLAG{Marty}
<hr>

### Cyber Threat Intelligence Automation
(NOTE: After the initial issues with the first code provided (API changes in twitter), they updated it to the following challenge)

Description - One of our junior software engineers build this script. What is the URL it is getting the user data from?
```
import tweepy
import requests

auth = tweepy.OAuth2BearerHandler("Bearer Token here")
api = tweepy.API(auth)

user = api.get_user(screen_name="joebiden")

for a, v in user.__dict__.items():
    if "url" not in str(a):
        continue

    r = requests.get(v)
    
    # Hmm interesting 
    if "hacker" in str(r.headers):
        print(r.headers)
        
    # Download images for further analysis
    if r.headers["Content-Type"] in ("image/png", "image/jpeg", "image/jpg"):
        with open(a+'.jpg', 'wb') as handler:
            handler.write(r.content)
```
Flag format: FLAG{http://completeAPIendpoint}

I spent a lot of time trying to get the code to run using twitter dev creds to no avail.

In the end, I did this from my phone in bed late one night using ChatGPT.

The prompt:
Explain this code
```
import tweepy
import requests

auth = tweepy.OAuth2BearerHandler("Bearer Token here")
api = tweepy.API(auth)

user = api.get_user(screen_name="joebiden")

for a, v in user.__dict__.items():
    if "url" not in str(a):
        continue

    r = requests.get(v)
    
    # Hmm interesting 
    if "hacker" in str(r.headers):
        print(r.headers)
        
    # Download images for further analysis
    if r.headers["Content-Type"] in ("image/png", "image/jpeg", "image/jpg"):
        with open(a+'.jpg', 'wb') as handler:
            handler.write(r.content)
```
Response:
```
This code is written in Python and uses the Tweepy and Requests libraries to interact with the Twitter API and 
download images from a user's Twitter profile. Here's a breakdown of what the code does:

    Imports the necessary libraries: tweepy for working with the Twitter API and requests for making HTTP requests.

    Initializes authentication with the Twitter API using a Bearer token.

    Creates a Tweepy API object using the previously configured authentication.

    Retrieves information about a Twitter user with the screen name "joebiden" using the api.get_user() method 
and stores it in the user variable.

    Iterates through the attributes (properties) of the user object using user.__dict__.items(). It's checking 
if any attribute name contains the substring "url". If it doesn't, the loop continues to the next attribute.

    For each attribute that contains "url" in its name, the code sends an HTTP GET request to the URL stored in 
the attribute's value (v). The response is stored in the variable r.

    The code checks if the response headers contain the string "hacker". If they do, it prints the headers. This 
part seems to be a form of debugging or exploration to identify potential suspicious headers.

    The code then checks if the "Content-Type" header in the response is one of "image/png", "image/jpeg", or 
"image/jpg". If it matches, the code assumes that the response contains an image and saves it to a file. The 
filename is derived from the attribute's name (a) with a ".jpg" extension.

In summary, this code fetches the Twitter profile of a user with the screen name "joebiden", checks for URLs in 
the user object, makes requests to those URLs, inspects response headers for potential signs of hacking, and 
downloads and saves images from those URLs if they are of valid image types.
```
My response question:
```
Is there a way to determine the full search URL that tweepy would create to the Twitter api endpoint for this code?
```
Response:
```
Yes, you can determine the full search URL to the Twitter API endpoint using the provided code. The code doesn't 
explicitly perform a search operation, but it interacts with a user's profile data using the Twitter API. To find 
the URL for the Twitter API endpoint that retrieves a user's profile information, you can combine the base Twitter 
API URL with the endpoint specific to retrieving user information.

The base Twitter API URL is: https://api.twitter.com/1.1/

The endpoint for retrieving user information is: users/show.json

When you combine these two components, you get the full URL for retrieving the profile information of a user with 
the screen name "joebiden":

https://api.twitter.com/1.1/users/show.json?screen_name=joebiden

Please note that Twitter's API endpoints and structure may change over time, so it's important to refer to the 
official Twitter API documentation for the most accurate and up-to-date information.
```
:+1: FLAG{https://api.twitter.com/1.1/users/show.json?screen_name=joebiden}
<hr>

