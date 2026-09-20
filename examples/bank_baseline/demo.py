#!/usr/bin/env python3
"""A readable local demonstration. --approve-demo simulates an operator approval."""
import argparse, json, pathlib, sys, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
def offline(event,args):
    if event in {'socket.connect','socket.getaddrinfo','socket.sendto','socket.bind'}:raise RuntimeError('offline demo')
sys.addaudithook(offline)
from baseline import Controller,MockBank,Task

def transfer(oid,amount,destination='a-vendor'):
    return {'operation_id':oid,'tool':'bank.transfer','arguments':{'source':'a-main','destination':destination,'amount_cents':amount}}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--approve-demo',action='store_true');options=parser.parse_args()
    transcript=[]
    with tempfile.TemporaryDirectory(prefix='pramagent-bank-demo-') as directory:
        root=pathlib.Path(directory);bank=MockBank(root/'bank.sqlite')
        controller=Controller(root/'control',bank,operator_token='local-demo-operator',clock=lambda:1_800_000_000)
        controller.configure(Task(
            can_transfer=True,
            allowed_operations=('bank.balance','bank.transfer'),
            readable_accounts=('a-main',),
        ),'local-demo-operator')
        def show(label,result):
            entry={'step':label,'result':result,'bank':bank.request('snapshot')};transcript.append(entry)
        # Task identity is supplied by the host application, not the model payload.
        agent_submit=lambda request:controller.submit('invoice-task',request)
        try:
            show('Initial synthetic accounts',{'status':'ready'})
            show('Permitted USD 100 transfer',agent_submit(transfer('small',10_000)))
            pending=agent_submit(transfer('large',100_000));show('USD 1,000 waits for approval',pending)
            show('Unapproved beneficiary',agent_submit(transfer('wrong-destination',10_000,'a-savings')))
            if options.approve_demo:
                show('SIMULATED OPERATOR approves exact USD 1,000 transfer',controller.approve('large',pending['digest'],reviewer='demo-human',token='local-demo-operator'))
            show('Retry original USD 100 operation; no second debit',agent_submit(transfer('small',10_000)))
            bank.drop_next_transfer_response=True
            show('Lost response after USD 10 commits',agent_submit(transfer('uncertain',1_000)))
            show('Receipt lookup reconciles USD 10; no second debit',agent_submit(transfer('uncertain',1_000)))
        finally:controller.close();bank.close()
    print(json.dumps({'mode':'offline synthetic bank','real_money':False,'operator_approval_is_simulated':options.approve_demo,'steps':transcript},indent=2))
if __name__=='__main__':main()
