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

We were given the image [McFly.png]

Using aperisolve - zsteg reveals the flag
:+1: FLAG{Marty}
<hr>
