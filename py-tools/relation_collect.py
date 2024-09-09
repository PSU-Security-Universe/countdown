import os
import subprocess
import time
from datetime import datetime

import relation_summary


do_remote_python = True



img_dir = '../image/'
pwd_path = img_dir + 'stretch.id_rsa'

port_createdtime_D = {}
port_deadtime_D = {}
port_pid_D = {}
port_killed_time_D = {}


def runcmd(command, timeout=5):
    ret = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                         encoding="utf-8")
    if ret.returncode == 0:
        return ret.stdout
    else:
        return 'ERROR'


last_port_s = set()


def get_all_file():
    
    id_str = os.getcwd().split('/')[-2]
    print(id_str)

    global last_port_s
    get_port_cmd = 'ps aux | grep qemu | grep ' + id_str
    ret_l = runcmd(get_port_cmd).split('\n')
    port_pid_D = {}

    port_l = []
    for l in ret_l:
        if 'hostfwd=tcp:' in l:
            port_str = l.split('hostfwd=tcp:')[1].split(' ')[0].split(':')[1][:-1]
            port_l.append(port_str)
            pid = ' '.join(l.split()).split(' ')[1]
            port_pid_D[port_str] = pid
    print('port_l', port_l)

    now_port_s = set(port_l)

    new_port_s = now_port_s.difference(last_port_s)
    last_port_s = now_port_s

    for port_str in port_l:
        if port_str not in port_createdtime_D:
            port_createdtime_D[port_str] = datetime.now()

    for port_str in port_l:
        print('~~~~~~~~~')
        run_time = (datetime.now() - port_createdtime_D[port_str]).seconds
        print(port_str + ' running ' + str(run_time))

        folder_path = './refcnt_records/' + port_str

        if port_str not in port_killed_time_D:
            port_killed_time_D[port_str] = 0
        folder_path += '_' + str(port_killed_time_D[port_str])

        runcmd('mkdir -p ' + folder_path, timeout=30)

        ssh = None

        try:
            if port_str in new_port_s:
                time_out = 120
            else:
                time_out = 120

            download_cmd = 'scp  -o "StrictHostKeyChecking no" -i ' + pwd_path + ' -P ' + port_str + ' root@localhost:/this-vm-finding* ' + folder_path

            print(download_cmd)
            print('downloading new relations... waiting for up to ' + str(time_out) + ' seconds...')
            res = runcmd(download_cmd, time_out)
            print('download success!')


            download_cmd = 'scp  -o "StrictHostKeyChecking no" -i ' + pwd_path + ' -P ' + port_str + ' root@localhost:/this-vm-pair* ' + folder_path

            print(download_cmd)
            print('downloading this-vm-pair... waiting for up to ' + str(time_out) + ' seconds...')
            res = runcmd(download_cmd, time_out)
            print('download success!')

            relation_summary.relation_summary_func()  # use all new relations to build new base for uploading

            upload_base_cmd = 'scp -i ' + pwd_path + ' -P ' + port_str + ' ' + relation_summary.realation_path_cross_history + ' ' + ' root@localhost:/kref/' + relation_summary.realation_path_cross_history
            print(upload_base_cmd)
            print('waiting for up to ' + str(time_out) + ' seconds...')
            res = runcmd(upload_base_cmd, time_out)
            print('upload realation_path_cross_history success!')

            upload_base_cmd = 'scp -i ' + pwd_path + ' -P ' + port_str + ' ' + relation_summary.refcnt_change_path_cross_history + ' ' + ' root@localhost:/kref/' + relation_summary.refcnt_change_path_cross_history
            print(upload_base_cmd)
            print('waiting for up to ' + str(time_out) + ' seconds...')
            res = runcmd(upload_base_cmd, time_out)
            print('upload refcnt_change_path_cross_history success!')

            if port_str in port_deadtime_D:
                port_deadtime_D.pop(port_str)


        except Exception as e:
            print('error happened! ', e)
            if ssh is not None:
                ssh.close()

            tmp_now = datetime.now()

            if port_str not in port_deadtime_D:
                port_deadtime_D[port_str] = tmp_now

            dead_time = (tmp_now - port_deadtime_D[port_str]).seconds
            if dead_time >600:
                print('port ' + port_str + ' is dead from ' + str(dead_time) + ' seconds ago')
                kill_cmd = 'kill ' + port_pid_D[port_str]
                print(kill_cmd)
                runcmd(kill_cmd)
            
                port_pid_D.pop(port_str)
                port_createdtime_D.pop(port_str)
                port_killed_time_D[port_str] += 1
                port_deadtime_D.pop(port_str)


def main():
    k = 0
    while True:
        k += 1
        print('turn', k)
        # get_all_file()

        try:
            get_all_file()
        except:
            pass

        # print('port_pid_D', port_pid_D)

        print()
        print('------------------------------------')

        time.sleep(150)


main()
