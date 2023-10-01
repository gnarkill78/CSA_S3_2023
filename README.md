# CSA_S3_2023
# CTF Writeups
## Writeups for the ADF Cyber Skills Association Season 3 challenges.
There were 32 challenges in total, 27 of which I was able to solve. The ones left unsolved were:
- Cipher This (Cryptography)
  - Had no idea how to proceed with this one. The only given clue was LPUKWOKVIRYQ
- Customary, my dear Watson (Reverse Engineering)
  - REVENG is not my thing obviously but I did start to learn a little about assembly language, obviously not enough though.
  - This one appeared to required an input file called 'Sherlock.jpeg' of a certain width and height. If that was satisfied, it would write a file called 'data.ana'
  - I got so far as working out the ratio required for the image and it would create data.ana but that was it.
- FUD Crypter Alpha (Reverse Engineering)
  - As above, REVENG is not my thing.
  - Running the binary printed 'some of the flag' which was 'FLA' then 'Flag? What flag?'
  - I couldn't work out anything beyond that even when looking at the binary in IDA/Ghidra/GDB/Radare2
- Nature is very fragile (Steganography)
  - This one was hard for a very obvious reason. It was created on this [website](https://www.pelock.com/products/steganography-online-codec)
  - My deduction was that brute force was the only way to tackle this one given the methods of encryption etc stated on the site
  - I tried writing a script that might aid in reversing the process but no luck
  - I ended up writing a script that engages the website (using selenium) to upload the image then iterate through the rockyou password list but this is a very slow process
  - I had 8 VMs running but still had no luck.
  - I'm leaving it running though just for fun now.
- Static (Steganography)
  - Had no idea with this one
  - Looked like a smaller image placed over the main image
  - Got nowhere.

Below are my writes to those that I did solve.

### Answer The Ultimate Question Of Life
Description - The following code snippet is a complex Python program that uses recursion 
for a given number. Your task is to analyse the code and identify the output:
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
Solution:
Plugged this straight into ChatGPT:
```
The code you've provided defines a recursive function called recursive_sum that calculates the
sum of all positive integers from 1 to a given number n. Then, it uses this function to calculate
the sum of integers from 1 to 7 and prints the result.

Here's how the code works step by step for input_num = 7:

    The recursive_sum function is called with n = 7.
    Since 7 is greater than 1, the else block is executed.
    The function returns 7 + recursive_sum(6).

Now, the function calls itself with n = 6:

    Since 6 is also greater than 1, the else block is executed.
    The function returns 6 + recursive_sum(5).

This process continues until the base case is reached, which is when n becomes 1. At that point, the
function returns 1 without making any further recursive calls.

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

Solution:
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

Solution:
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

Solution:
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

### Dont call me shurly
Description - Decode the string to find the flag!
```
import base64

def decode_flag(encoded_flag):
    decoded_flag = base64.b64decode(encoded_flag).decode('utf-8')
    return decoded_flag

encoded_flag = "Q2FudCBtZSBhIGZsYWc="
flag = decode_flag(encoded_flag)
print(flag)
```

Enter the flag for the challenge in the format FLAG{enter_th_e_flag}

Solution:
I used chatGPT for this and it returned 'Can me a flag' which ended up wrong.

I then used Bard and it gave me 'Cant me a flag' which was correct

:+1: FLAG{Cant_me_a_flag}
<hr>

### Encrypted Text
Description - This message was intercepted. Can you tells me what it says?

Lqsxw IODJ{Vwhood}

Solution:
Using dcode cipher identier put ROT at top of list

ROT returned Input FLAG{Stella}

:+1: FLAG{Stella}
<hr>

### ET Phone Home
Description - What is the URL I can find this image at [Lookup.png](https://github.com/gnarkill78/CSA_S3_2023/blob/main/Lookup.png)?

Flag format: FLAG{url}

Solution:
Used the good ol' Google reverse image search for this one

:+1: FLAG{https://fifthdomain.com.au/}
<hr>

### Hidden Creds
Description - I made an authentication client for my secret server! It has some saved creds inside it, but you'll never find it
because I protected the binary script! Ha!
[Hidden Creds](https://github.com/gnarkill78/CSA_S3_2023/blob/main/Hidden%20Creds.zip)

Solution:
Turns out didn't need to run any deobfuscation tool, all that was needed was a memory dump.

Found a script called memdump.py (here - https://medium.com/@liad_levy/reverse-pyarmor-obfuscated-python-script-using-memory-dump-technique-9823b856be7a)

Kicked off script.py and in another window, ran ps -as to find the PID
Ran memdump.py against that PID which created a PID.dump file
Ran strings on dump file (strings PID.dump > process.dump)
Then cat process.dump | grep FLAG and voila.

:+1: FLAG{Y0u_c4n_just_rec3ive_creds}
<hr>

### I wish I could see these machines
Description - We've been tracking the progress of FOVIO (https://www.reddit.com/r/MachE/comments/nxqjsi/fords_dms_driver_monitoring_systems/)
for some time. In which suburb did the Chief Scientist at this company obtain their Diploma?

Flag format: FLAG{Suburb}

Solution:
Google search links FOVIO to company Seeingmachines

The chief scientist is Sebastien Rougeaux

His LinkedIn acct reveals his got his Diploma in Paris, Institut d’Informatique d’Entreprise to be precise.

A search for that institution reveals it's in Évry. This one doesn't need the accent.

:+1: FLAG{Evry}
<hr>

### Javap
Description - I got a file dump, but what do I mean?
```
public class SecAccess
  minor version: 0
  major version: 52
  flags: ACC_PUBLIC, ACC_SUPER
Constant pool:
   #1 = Methodref          #15.#27        // java/lang/Object."<init>":()V
   #2 = String             #28            // _!@abcdefghijklmnopqrstuvwxyz
   #3 = String             #29            // FLAG{
   #4 = Class              #30            // java/lang/StringBuilder
   #5 = Methodref          #4.#27         // java/lang/StringBuilder."<init>":()V
   #6 = Methodref          #4.#31         // java/lang/StringBuilder.append:(Ljava/lang/String;)Ljava/lang/StringBuilder;
   #7 = Methodref          #32.#33        // java/lang/String.charAt:(I)C
   #8 = Methodref          #4.#34         // java/lang/StringBuilder.append:(C)Ljava/lang/StringBuilder;
   #9 = Methodref          #4.#35         // java/lang/StringBuilder.toString:()Ljava/lang/String;
  #10 = Methodref          #32.#36        // java/lang/String.length:()I
  #11 = String             #37            // }
  #12 = Fieldref           #38.#39        // java/lang/System.out:Ljava/io/PrintStream;
  #13 = Methodref          #40.#41        // java/io/PrintStream.println:(Ljava/lang/String;)V
  #14 = Class              #42            // SecAccess
  #15 = Class              #43            // java/lang/Object
  #16 = Utf8               <init>
  #17 = Utf8               ()V
  #18 = Utf8               Code
  #19 = Utf8               LineNumberTable
  #20 = Utf8               main
  #21 = Utf8               ([Ljava/lang/String;)V
  #22 = Utf8               StackMapTable
  #23 = Class              #44            // "[Ljava/lang/String;"
  #24 = Class              #45            // java/lang/String
  #25 = Utf8               SourceFile
  #26 = Utf8               SecAccess.java
  #27 = NameAndType        #16:#17        // "<init>":()V
  #28 = Utf8               _!@abcdefghijklmnopqrstuvwxyz
  #29 = Utf8               FLAG{
  #30 = Utf8               java/lang/StringBuilder
  #31 = NameAndType        #46:#47        // append:(Ljava/lang/String;)Ljava/lang/StringBuilder;
  #32 = Class              #45            // java/lang/String
  #33 = NameAndType        #48:#49        // charAt:(I)C
  #34 = NameAndType        #46:#50        // append:(C)Ljava/lang/StringBuilder;
  #35 = NameAndType        #51:#52        // toString:()Ljava/lang/String;
  #36 = NameAndType        #53:#54        // length:()I
  #37 = Utf8               }
  #38 = Class              #55            // java/lang/System
  #39 = NameAndType        #56:#57        // out:Ljava/io/PrintStream;
  #40 = Class              #58            // java/io/PrintStream
  #41 = NameAndType        #59:#60        // println:(Ljava/lang/String;)V
  #42 = Utf8               SecAccess
  #43 = Utf8               java/lang/Object
  #44 = Utf8               [Ljava/lang/String;
  #45 = Utf8               java/lang/String
  #46 = Utf8               append
  #47 = Utf8               (Ljava/lang/String;)Ljava/lang/StringBuilder;
  #48 = Utf8               charAt
  #49 = Utf8               (I)C
  #50 = Utf8               (C)Ljava/lang/StringBuilder;
  #51 = Utf8               toString
  #52 = Utf8               ()Ljava/lang/String;
  #53 = Utf8               length
  #54 = Utf8               ()I
  #55 = Utf8               java/lang/System
  #56 = Utf8               out
  #57 = Utf8               Ljava/io/PrintStream;
  #58 = Utf8               java/io/PrintStream
  #59 = Utf8               println
  #60 = Utf8               (Ljava/lang/String;)V
{
  public SecAccess();
    descriptor: ()V
    flags: ACC_PUBLIC
    Code:
      stack=1, locals=1, args_size=1
         0: aload_0
         1: invokespecial #1                  // Method java/lang/Object."<init>":()V
         4: return
      LineNumberTable:
        line 1: 0

  public static void main(java.lang.String[]);
    descriptor: ([Ljava/lang/String;)V
    flags: ACC_PUBLIC, ACC_STATIC
    Code:
      stack=3, locals=5, args_size=1
         0: ldc           #2                  // String _!@abcdefghijklmnopqrstuvwxyz
         2: astore_1
         3: ldc           #3                  // String FLAG{
         5: astore_2
         6: iconst_5
         7: istore_3
         8: iconst_5
         9: istore        4
        11: iload         4
        13: bipush        11
        15: if_icmpge     56
        18: new           #4                  // class java/lang/StringBuilder
        21: dup
        22: invokespecial #5                  // Method java/lang/StringBuilder."<init>":()V
        25: aload_2
        26: invokevirtual #6                  // Method java/lang/StringBuilder.append:(Ljava/lang/String;)Ljava/lang/StringBuilder;
        29: aload_1
        30: iload_3
        31: invokevirtual #7                  // Method java/lang/String.charAt:(I)C
        34: invokevirtual #8                  // Method java/lang/StringBuilder.append:(C)Ljava/lang/StringBuilder;
        37: invokevirtual #9                  // Method java/lang/StringBuilder.toString:()Ljava/lang/String;
        40: astore_2
        41: iload_3
        42: iconst_3
        43: imul
        44: aload_1
        45: invokevirtual #10                 // Method java/lang/String.length:()I
        48: irem
        49: istore_3
        50: iinc          4, 1
        53: goto          11
        56: new           #4                  // class java/lang/StringBuilder
        59: dup
        60: invokespecial #5                  // Method java/lang/StringBuilder."<init>":()V
        63: aload_2
        64: invokevirtual #6                  // Method java/lang/StringBuilder.append:(Ljava/lang/String;)Ljava/lang/StringBuilder;
        67: ldc           #11                 // String }
        69: invokevirtual #6                  // Method java/lang/StringBuilder.append:(Ljava/lang/String;)Ljava/lang/StringBuilder;
        72: invokevirtual #9                  // Method java/lang/StringBuilder.toString:()Ljava/lang/String;
        75: astore_2
        76: getstatic     #12                 // Field java/lang/System.out:Ljava/io/PrintStream;
        79: aload_2
        80: invokevirtual #13                 // Method java/io/PrintStream.println:(Ljava/lang/String;)V
        83: return
      LineNumberTable:
        line 4: 0
        line 5: 3
        line 6: 6
        line 7: 8
        line 8: 18
        line 9: 41
        line 7: 50
        line 11: 56
        line 12: 76
        line 13: 83
      StackMapTable: number_of_entries = 2
        frame_type = 255 /* full_frame */
          offset_delta = 11
          locals = [ class "[Ljava/lang/String;", class java/lang/String, class java/lang/String, int, int ]
          stack = []
        frame_type = 250 /* chop */
          offset_delta = 44
}
SourceFile: "SecAccess.java"
```

Solution:
The clue here was that the dump file dumped the class data as well so in order to get it to work, the class data needed
to be removed and the java file cleaned up. I did this all in windows.
```
public class SecAccess {
    public SecAccess() {
        super();
    }

    public static void main(String[] args) {
        String _1 = "_!@abcdefghijklmnopqrstuvwxyz";
        String _2 = "FLAG{";
        int _3 = 5;
        int _4 = 5;

        while (_4 < 11) {
            StringBuilder sb = new StringBuilder();
            sb.append(_2);
            sb.append(_1.charAt(_3));
            _2 = sb.toString();
            _3 = (_3 * 3) % _1.length();
            _4++;
        }

        StringBuilder finalString = new StringBuilder();
        finalString.append(_2);
        finalString.append("}");

        System.out.println(finalString.toString());
    }
}
```
This was saved as SecAccess.java

Then, from the command line in order to create the class file, run 'javac SecAccess.java'

SecAccess.class was created.

Finally run 'java SecAccess' to get the flag.

:+1: FLAG{cmnqzx}
<hr>

### Jet-setter
Description - In March, Mark Benioff boarded his Gulfstream at Phoenix Sky Harbor International Airport (PHX) Arizona. 

Where did he get off?

Flag format: FLAG{Airportname} for example: FLAG{Nadi}

Solution:
OSINT reveals the tail number of his aircraft as N650HA (A gulfstearm)

Celebrityprivatejettracker gives some data for March 23 but not what we're after

https://globe.adsbexchange.com is more help

Enter N650HA in the search which gives no data but on the left, expand History and change the date range

Start at 2023-03-01 and click next

On 10 Mar, the path shows a departure from PHX heading to Hawaii

Zooming in you can see it lands at Kona International Airport

:+1: FLAG{Kona}
<hr>

### Redditdetective
Description - Redditective We believe that this redditor leaked confidential information to our rivals and we need
you to take a look. Could you see if there is any leads from his account? u/ChaoticLlama12345 Flag format:
FLAG{text_text_text_text_text}

Solution:
Go to waybackmachine

Search the first post - https://www.reddit.com/user/ChaoticLlama12345/comments/14f9iee/hi_reddit/

Indicates it's been saved 2 times - click the date on the calendar

Open the pastebin link
```
Agent Delta, this is a covert transmission for your eyes only. The mission is a go, codename "Operation Midnight Serpent."
Target acquisition confirmed at coordinates 39.8712° N, 104.9962° W. 

Exercise extreme caution as the target is considered high-profile and surrounded by tight security.
 
Your primary objective is to infiltrate the facility undetected and retrieve the classified documents from the secure vault
in Room 315. 

Intel suggests that the vault's access code is a sequence of numbers related to the target's birthdate. Use your exceptional
lock-picking skills to gain entry.
 
Secondary objective: Extract any information on "Project Pandora" from the mainframe located in the basement. 

This project poses a significant threat to national security, and any data acquired will aid our ongoing investigation.
 
Remember, time is of the essence. Complete the mission swiftly and discreetly, leaving no trace of your presence. Be aware
of potential double agents within the organization. Trust no one.
 
Once you have successfully obtained the documents and extracted the data, rendezvous with your extraction team at the
designated location: The Old Mill by the river, precisely at 2300 hours. 

Prepare for immediate extraction and secure the sensitive materials.
 
Exercise extreme caution, Agent Delta, as the success of "Operation Midnight Serpent" rests in your capable hands. 

Trust your training, rely on your instincts, and above all, maintain your cover. Good luck, Agent. The fate of our nation
depends on your success.
 
This transmission will self-destruct in 5...4...3...2...1...

FLAG{y0u_th1nk_y0ud_g3t_4w45}
``` 
:+1: FLAG{y0u_th1nk_y0ud_g3t_4w45}
<hr>

### Reverso
Description - ???

Solution:
Extract zip file [reverso.zip](https://github.com/gnarkill78/CSA_S3_2023/blob/main/reverso.zip)

Open crackme file in notepad

Search for flag

:+1: FLAG{Y0u_4r3_4_r3v3r53_3ng1n33r}
<hr>

### Rockapi
Description - They told me to Rock your API, so I built an API that rocks 
[Zip File](https://github.com/gnarkill78/CSA_S3_2023/blob/main/rockapi.zip)! 
What's the admin's password? URL port: 8080 Wrap it in FLAG{}

Solution:
Firstly I worked out that the url to get a login prompt is
http://platf-loadb-6nnucudws0q7-c79f2644d7a58110.elb.ap-southeast-2.amazonaws.com:8080/api/users

This is also Basic Authentication meaning the username:password is sent as base64

Brute forcing using Burp and Hydra were no good (had to remember to force base64)

I opened Ghidra to look at the binary deeper and found what looked like a password 'apiadminp@ssw0rd'

After many many many many attempts with this password, of which I am sure I had tried this several times, I was able to login,
using the URL http://platf-loadb-6nnucudws0q7-c79f2644d7a58110.elb.ap-southeast-2.amazonaws.com:8080/api/users
with username 'apiadmin' and password 'apiadminp@ssw0rd' which then presented the following in JSON form:
```
{
    "users": [
        {
            "id": "1",
            "username": "admin",
            "password": "$2a$05$1tmIXGzh9/86ZdwxS1yqYuLCn76TM6CQuG9S6AqP5wEMdmXwrCyF6",
            "description": "I am groot"
        },
        {
            "id": "2",
            "username": "bob",
            "password": "$2a$05$nf0KzyjlgnWD8y6Rwq5UzON5gTqH62.OxS2Y0KpZVVepvwrRhAJ1C",
            "description": "I wish I am groot"
        }
    ]
}
```
From there, I saved the hash to a file and used hashid to identify the hash for admin as bcrypt
```
	└─$ hashid -m hash.txt
	--File 'hash.txt'--
	Analyzing '$2a$05$1tmIXGzh9/86ZdwxS1yqYuLCn76TM6CQuG9S6AqP5wEMdmXwrCyF6'
	[+] Blowfish(OpenBSD) [Hashcat Mode: 3200]
	[+] Woltlab Burning Board 4.x
	[+] bcrypt [Hashcat Mode: 3200]
	--End of file 'hash.txt'--       
```
Tried hashcat to crack but it errored. I used john the ripper in the end:
```
	└─$ john --wordlist=/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --format=bcrypt hash.txt
	Using default input encoding: UTF-8
	Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
	Cost 1 (iteration count) is 32 for all loaded hashes
	Will run 4 OpenMP threads
	Press 'q' or Ctrl-C to abort, almost any other key for status
	motorola         (?)
	1g 0:00:00:00 DONE (2023-09-08 17:12) 1.136g/s 2372p/s 2372c/s 2372C/s 268..264
	Use the "--show" option to display all of the cracked passwords reliably
	Session completed.
```
Password was 'motorola'

:+1: FLAG{motorola}
<hr>

### Secret Invasion
Description - We're excited about the Secret Invasion. We think we know who the villain really is. Can you work it out!?
[Zip File](https://github.com/gnarkill78/CSA_S3_2023/blob/main/Invasion.zip)

Solution:
This is a steg one. Loaded it into aperisolve again.

Ensure zsteg is selected.

Scroll through the zsteg output and find Ben Mendelsohn

:+1: FLAG{Ben_Mendelsohn}
<hr>

### That's not an IP address
Description - Where does this address originate? 1.0.8.0

Flag format: FLAG{Text}

Solution:
I'm not 100% on this one as I didn't take notes at the time so can't fully remember.
IIRC, I did a whois search which indicated China.
```
% Information related to '1.0.8.0 - 1.0.15.255'

% Abuse contact for '1.0.8.0 - 1.0.15.255' is 'email@chinatelecom.cn'

inetnum:        1.0.8.0 - 1.0.15.255
netname:        CHINANET-GD
descr:          CHINANET Guangdong province network
descr:          Data Communication Division
descr:          China Telecom
country:        CN
admin-c:        CH93-AP
tech-c:         IC83-AP
abuse-c:        AC1573-AP
status:         ALLOCATED PORTABLE
remarks:        service provider
notify:         email@189.cn
mnt-by:         APNIC-HM
mnt-lower:      MAINT-CHINANET-GD
mnt-irt:        IRT-CHINANET-CN
last-modified:  2021-06-15T08:05:54Z
source:         APNIC
```
:+1: flag{Guangdong}
<hr>

### Think it through
Description - We intercepted a message: ZulhrfVul8

Can you find out what it says?

Flag format is FLAG{Nicefive3}

Solution:
Dcode cipher identifier indicates ROT Cipher top return

Default brute force gives 'SneakyOne8' but have to remember that doesn't rotate the number

Cyber Chef is good for that and rotating numbers give 'SneakyOne7'

:+1: FLAG{SneakyOne7}
<hr>

### Times New Roman
Description - Times New Roman In ancient times, the Romans used to philosophize and hang out at the aqueducts. We now live in 
the age of the interet and the romans have gotten better at their security! Are you up for the challenge? Let the
decryption begin in the quest for hidden knowledge! [Zip File](https://github.com/gnarkill78/CSA_S3_2023/blob/main/cipher.zip)

JAFKQ/1uh6u.@u1/7.@6/q4uy6W

Solution:
After trying many forms of different ciphers I had an apiphany about keyboards.

Turns out, after looking at my keyboard and seeing things that started to align,
it's actually a keyboard shift cipher (found on dcode)

https://www.dcode.fr/keyboard-shift-cipher

:+1: FLAG{m0rd3rnr0m4n3mp1re3}
<hr>

### Truck Truck Truck
Description - [Image](https://github.com/gnarkill78/CSA_S3_2023/blob/main/truck.png)

Solution:
Do a reverse image search

I found some reddit posts talking about emissions etc and it mentioned (with the exact pic of truck)

"North Macedonia, western part of the country, on the E-65 somewhere between Kichevo and Arbinovo"

You can actually find this truck on the highway and backtracking gets you into Kichevo

Trick here in the flag was to keep the accent on the c

:+1: FLAG{Kičevo}
<hr>

### Vigenere
Description - You intercepted the following ciphertext: "Imvpg xwbpv, J iw el Uzoo xbkdsjz". 
The ciphertext has been encrypted using a Vigenère cipher with an unknown keyword.

When submitting your answer, be mindful that it is case sensitive and use _ in place of spaces! 

Flag format: FLAG{Input_the,_flag_here_you_Just_found}

Solution:
Use dcode for this one and bruteforce with Vigenere Cipher

It cracks the key - BIKES

And spits out 'Hello world, I am at Trek factory'

:+1: FLAG{Hello_world,_I_am_at_Trek_factory}
<hr>

### Wagner
Description - It's early morning (~1am (GMT+3)), June 23, 2023. We've just received reports of a column of Wagner mercenaries 
crossing a border checkpoint into Russia.

We need to confirm these details with satellite imagery. What is the name of the border checkpoint they crossed?

Flag format: FLAG{Bordercheckpoint}

Solution:
This was a pain but you can find an [Image](https://github.com/gnarkill78/CSA_S3_2023/blob/main/Wagner.png) of the routes taken.

Some painful research leads it to Novoshakhtinsk but it's the alternate spelling - Novosachtinsk

:+1: FLAG{Novosachtinsk}
<hr>

### Water Works
Description - We know that Legit Wun will be staying with his brother in July. [Instagram site](https://www.instagram.com/legit.wun/)

Can you locate the city they will be in?

Flag format: FLAG{City}

Solution:
I used google to search for the road intersection of 49th St and Jerelyn PL (from the images found on Instagram post)

It's in Milwaukee WI, USA

Catch however is that the flag is not Milwaukee, it was in Greenfield.

:+1: FLAG{Greenfield}
<hr>

### Website Self Defence
Description - I wrote my own blog framework! I just learned python flask recently, it's super easy to get started.

But apparently some kiddies thought it would be funny to hack my website and leak my files...

So I've had to implement some self-defense measures. Take that, skids!

URL port: 5000

Flag format: FLAG{you_have_found_the_flag}

[Container URL](http://platf-loadb-r6hholsy48l2-dcc802b3713ed02a.elb.ap-southeast-2.amazonaws.com:5000/)

Solution:
Although I did solve this one, I can't remember how I've done it at this stage and hadn't written it down.
Solution to come.
<hr>

### What's A Pub Key?
Description - I told my friends I wanted to build an authentication system like the one they use with JWTs but cooler! They 
said I need a pub key to sign and verify cookies.. Pub key? To which pub?
[Zip File](https://github.com/gnarkill78/CSA_S3_2023/blob/main/pubauthsrv.zip)

Solution:
This was a pain in the you know what!!

Using the original pubserv.go code, I eventually hard coded the pubkey string
that was being returned from the website given in the challenge.

This is what I added which allowed me to use the pubkey as a byte array instead, meaning when I ran the
entire program locally, I could register a user named admin (modify code again) and then login as admin
to get a cookie.

```
const pubkeyStr = "937eRhvE0bqx81t3G9o79LOkkR4CK9Cyhvt8-QJ-s1H2A6uSwukUI0CYUlc3WbmIAa3VTo4Jm9RF5F0Af4DzmQ"

func init() {
    pubkey = &[64]byte{}
    decodedPubstr, err := base64.RawURLEncoding.DecodeString(pubkeyStr)
    if err != nil {
        log.Fatal("Error decoding pubkeyStr:", err)
        return
    }
    copy(pubkey[:], decodedPubstr)
}
```

The pubkey array ended up as [247 126 222 70 27 196 209 186 177 243 91 119 27 218 59 244 179 164 145 30 2 43 208 178 134 251 124 249 2 126 179 81 246 3 171 146 194 233 20 35 64 152 82 87 55 89 185 136 1 173 213 78 142 9 155 212 69 228 93 0 127 128 243 153]

I tested it locally and on the site using a user called rocky to check I got the same cookie
```
┌──(user㉿violet)-[~]
└─$ curl -X POST -H "Content-Type: application/json" -d '{"username": "rocky","password": "password"}' 127.0.0.1:80/rego
"rocky"                                                                                                                                                                                                                                                                       
┌──(user㉿violet)-[~]
└─$ curl -X POST -H "Content-Type: application/json" -d '{"username": "rocky","password": "password"}' 127.0.0.1:80/login
{
    "cookie": "P5Q-c_EQWhkUbagDC3klwsv0SQ6JdK9zDZLws3PzWjjdjcqiHlJMWLsxKDraTgU6za_fOXuaEOa5i2NhEmY0DnJvY2t5"
} 
┌──(user㉿violet)-[~]
└─$ curl -X POST -H "Content-Type: application/json" -d '{"username": "rocky","password": "password"}' platf-loadb-1dnrzrpf9f9mt-1293434102.ap-southeast-2.elb.amazonaws.com:80/rego
"rocky"                                                                                                                                                                                                                                                                       
┌──(user㉿violet)-[~]
└─$ curl -X POST -H "Content-Type: application/json" -d '{"username": "rocky","password": "password"}' platf-loadb-1dnrzrpf9f9mt-1293434102.ap-southeast-2.elb.amazonaws.com:80/login
{
    "cookie": "P5Q-c_EQWhkUbagDC3klwsv0SQ6JdK9zDZLws3PzWjjdjcqiHlJMWLsxKDraTgU6za_fOXuaEOa5i2NhEmY0DnJvY2t5"
} 
```
Did the same with admin and voila
```
──(user㉿violett)-[~]
└─$ curl -X POST -H "Content-Type: application/json" -d '{"username": "admin","password": "password"}' 127.0.0.1:80/rego
"admin"                                                                                                                                                                                                                                                                       
┌──(user㉿violett)-[~]
└─$ curl -X POST -H "Content-Type: application/json" -d '{"username": "admin","password": "password"}' 127.0.0.1:80/login
{
    "cookie": "NA3kOxFS095PEaMdQa97fuHlMGU_KY4GNk1NdUHbWxpRMxSxCSJiwlvS5jv2dmPHB2rXkCcgl7eaOIG4sFWpDmFkbWlu"
} 
```
So when I logged in as admin, my cookie was
NA3kOxFS095PEaMdQa97fuHlMGU_KY4GNk1NdUHbWxpRMxSxCSJiwlvS5jv2dmPHB2rXkCcgl7eaOIG4sFWpDmFkbWlu

I then used burp suite repeater to add the cookie to a GET request for /secret and bingo, the flag.

:+1: FLAG{th3_publ1c_k3y_was_the_priv4te_key}
<hr>

### Where is he?
Description - Someone sent me a photo of this beautiful dog! I want to go pat him, help me find him. [photo](https://github.com/gnarkill78/CSA_S3_2023/blob/main/ace.jpeg)

Flag is of format FLAG{StreetName} for example FLAG{Oxford}

Solution:
I used aperisolve.com for this one to grab the Exif data (exiftool will work fine)

There's some coordinates listed in the Exif Data

XPComment	-35.32136336368097, 149.05575597329124

Put these into any lat long finder and you get the address '3 Kirkpatrick St, Weston ACT 2611, Australia'

:+1: FLAG{Kirkpatrick}
<hr>

### Who is on my machine?
Description - I had a call with a call center and they said they installed an anti-virus on my machine, but I've noticed my computer 
mouse moving when I'm not touching it. I took it into a repair center and they couldn't figure it out but said I should take it to a 
specialist to find out what's happening.

I tried to open the file but it's got a password so please help me!

The Flag is in the format of FLAG{<creator_account>_<new_account>}

Solution:
Bruteforce the [Zip File](https://github.com/gnarkill78/CSA_S3_2023/blob/main/machine.zip)

I used zip2john in kali - zip2john logs.zip > logs.txt
then
sudo john --format=zip logs.txt
which gave output
```
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Loaded hashes with cost 1 (HMAC size) varying from 52577 to 526836
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
starwars         (logs.zip/application.evtx)
starwars         (logs.zip/sec.evtx)
starwars         (logs.zip/system.evtx)
3g 0:00:00:02 DONE 2/3 (2023-08-19 17:19) 1.456g/s 57778p/s 65734c/s 65734C/s 123456..ferrises
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Open the sec.evtx file in Windows Event Viewer and search through the logs

Find user 'sododgy'

:+1: FLAG{vboxuser_sododgy}
<hr>

### World Tour
Description - On June 21, Legit Wun [Instagram site](https://www.instagram.com/legit.wun/) undertook an international journey.

We need you to track each of the cities they passed through!

The flag format will be FLAG{Florida_Newrleans_NewYork_Seattle_Brisbane}

Solution:
Identify the locations from the images mainly using reverse image search:
- Canberra
- Sydney
- Singapore
- Helsinki
- Lahti

:+1: FLAG{Canberra_Sydney_Singapore_Helsinki_Lahti}
<hr>
