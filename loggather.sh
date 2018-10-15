#!/bin/bash


# If you notice any bugs or if you have any comments, suggestions or concerns
# Please email me at ashwinramki@gmail.com


# This script will collect most of the logs/outputs required
# to troubleshoot any generic issues with linux.


## LINUX LOGGATHER VERSION 1.0  BUILD DATE : October 15, 2018 ##

sig_trap () {

    echo -e "\n\n\n\nCleaning up & Terminating on user request .................\n\n"
    rm -rf "${BASE_DIR}"

}

dir_structure () {

    touch "${BASE_DIR}/error.out"
    mkdir -p "${BASE_DIR}/etc/sysconfig/network-scripts"
    mkdir -p "${BASE_DIR}/etc/udev/rules.d"
    mkdir "${BASE_DIR}/networking"
    mkdir "${BASE_DIR}/dev"
    mkdir "${BASE_DIR}/etc/lvm"
    mkdir "${BASE_DIR}/pam"
    mkdir "${BASE_DIR}/proc"
    mkdir "${BASE_DIR}/boot"
    mkdir "${BASE_DIR}/cron"
    # the docker contents in var/lib can be quite huge, hence commenting it out
    #mkdir "${BASE_DIR}/var_lib_docker_containers"
    mkdir "${BASE_DIR}/usr"
    mkdir "${BASE_DIR}/nfs"

}


# Prevents creating empty files
cmd_check () {
    if ! eval "timeout 20 $1" >> "$2" 2>> "${BASE_DIR}/error.out" ;
    then
        echo -e "\nCommand $1 had no output or timed out after 20 secondsb\n" >> "${BASE_DIR}/error.out"
        rm -f "$2"
    fi
}


server_info () {

    cmd_check "date '+%S:%M:%H:%d:%m:%Y'" "${BASE_DIR}/date_S_M_H_d_m_Y"
    cmd_check "date '+%m/%d/%y %H:%M:%S'" "${BASE_DIR}/date_m_d_y_H_M_S"
    cmd_check "date '+%d/%m/%y'" "${BASE_DIR}/date_d_m_y"

    cmd_check "hostnamectl" "${BASE_DIR}/hostnamectl"
    cmd_check "timedatectl" "${BASE_DIR}/timedatectl"
    cmd_check "uname -a" "${BASE_DIR}/uname_a"
    cmd_check "rpm -qa" "${BASE_DIR}/rpm_qa"
    cmd_check "rpm -aqi" "${BASE_DIR}/rpm_aqi"
    cmd_check "lsmod" "${BASE_DIR}/lsmod"
    cmd_check "ls -lAtr /dev" "${BASE_DIR}/ls_dev"
    cmd_check "env" "${BASE_DIR}/env"
    cmd_check "dmidecode" "${BASE_DIR}/dmidecode"
    cmd_check "lspci -vv" "${BASE_DIR}/lspci_vv"
    cmd_check "free" "${BASE_DIR}/free"
    cmd_check "free -m" "${BASE_DIR}/free_m"
    cmd_check "ps -eLf" "${BASE_DIR}/ps_eLf"
    cmd_check "ps auxww" "${BASE_DIR}/ps_auxww"
    cmd_check "ps eaf" "${BASE_DIR}/ps_eaf"
    cmd_check "ps -elf" "${BASE_DIR}/ps_elf"
    cmd_check "ps -ef" "${BASE_DIR}/ps_ef"
    cmd_check "last reboot" "${BASE_DIR}/reboot"
    cmd_check "sysctl -a" "${BASE_DIR}/sysctl_a"
    cmd_check "ulimit -Ha" "${BASE_DIR}/ulimit_Ha"
    cmd_check "ulimit -Sa" "${BASE_DIR}/ulimit_Sa"
    cmd_check "id" "${BASE_DIR}/id"
    cmd_check "uptime" "${BASE_DIR}/uptime"
    cmd_check "journalctl -lu docker" "${BASE_DIR}/journalctl_lu_docker"
    cmd_check "systemctl status -l docker" "${BASE_DIR}/systemctl_status_l_docker"
    cmd_check "systemctl status -l firewalld" "${BASE_DIR}/systemctl_status_l_firewalld"

    cmd_check "systemctl list-units" "${BASE_DIR}/systemctl_list_units"
    cmd_check "systemctl list-unit-files" "${BASE_DIR}/systemctl_list_unit_files"
    cmd_check "systemctl list-dependencies" "${BASE_DIR}/systemctl_list_dependencies"
    cmd_check "systemd-analyze blame" "${BASE_DIR}/systemd_analyze_blame"
    cmd_check "systemd-analyze plot" "${BASE_DIR}/systemd_analyze_plot"
    cmd_check "systemd-cgls -alk" "${BASE_DIR}/systemd_cgls_alk"
    cmd_check "systemd-cgtop -n1" "${BASE_DIR}/systemd_cgtop"


    cmd_check "dmesg" "${BASE_DIR}/dmesg"
    cmd_check "lsblk" "${BASE_DIR}/lsblk"
    cmd_check "lsblk -S" "${BASE_DIR}/lsblk_S"
    cmd_check "blkid" "${BASE_DIR}/blkid"
    cmd_check "lsscsi -s" "${BASE_DIR}/lsscsi_s"
    cmd_check "lsscsi -lll" "${BASE_DIR}/lsscsi_lll"

    cmd_check "df" "${BASE_DIR}/df"
    cmd_check "df -h" "${BASE_DIR}/df_h"
    cmd_check "mount -v" "${BASE_DIR}/mount_v"
    cmd_check "ls -Altr /var/lib/docker/overlay" "${BASE_DIR}/ls_docker_overlay"
    cmd_check "xfs_info -V" "${BASE_DIR}/xfs_info_V"
    cmd_check "xfs_info /var/lib/docker/overlay" "${BASE_DIR}/xfs_info_docker_overlay"

    cmd_check "/sbin/powermt display dev=all" "${BASE_DIR}/dev/powermt_display_dev_all"
    cmd_check "ls -laR /dev/sd*" "${BASE_DIR}/dev/ls_laR_sd"
    cmd_check "ls -laR /dev/hd*" "${BASE_DIR}/dev/ls_laR_hd"
    cmd_check "ls -laR /dev/dasd*" "${BASE_DIR}/dev/ls_laR_dasd"
    cmd_check "ls -laR /dev/cciss" "${BASE_DIR}/dev/ls_laR_cciss"
    cmd_check "ls -laR /dev/dm-*" "${BASE_DIR}/dev/ls_laR_dm"
    cmd_check "fdisk -l" "${BASE_DIR}/dev/fdisk_l"
    cmd_check "udisksctl status" "${BASE_DIR}/dev/udisksctl_status"
    cmd_check "udisksctl dump" "${BASE_DIR}/dev/udisksctl_dump"
    cmd_check "multipath -ll" "${BASE_DIR}/dev/multipath_ll"
    cmd_check "multipath -d -v3" "${BASE_DIR}/dev/multipath_d_v3"
    cmd_check "echo 'show config' | multipathd -k" "${BASE_DIR}/dev/multipath_k_show_config"
    cmd_check "echo 'show paths' | multipathd -k" "${BASE_DIR}/dev/multipath_k_show_paths"
    cmd_check "dmsetup ls" "${BASE_DIR}/dev/dmsetup_ls"
    cmd_check "dmsetup info" "${BASE_DIR}/dev/dmsetup_info"
    cmd_check "dmsetup status" "${BASE_DIR}/dev/dmsetup_status"
    cmd_check "dmsetup deps" "${BASE_DIR}/dev/dmsetup_deps"

    for dev in $( fdisk -l | grep 'Disk /dev' | awk '{print $2}' | cut -f1 -d':' )
    do
        hdparm "$dev" &>> "${BASE_DIR}/hdparm_all_devices"
        echo -e "\n" >> "${BASE_DIR}/hdparm_all_devices"
    done

    {
	       	
        cp -pRL /proc/cpuinfo "${BASE_DIR}/proc"
        cp -pRL /proc/devices "${BASE_DIR}/proc"
        cp -pRL /proc/interrupts "${BASE_DIR}/proc"
        cp -pRL /proc/iomem "${BASE_DIR}/proc"
        cp -pRL /proc/ioports "${BASE_DIR}/proc"
        cp -pRL /proc/meminfo "${BASE_DIR}/proc"
        cp -pRL /proc/pci "${BASE_DIR}/proc"
        cp -pRL /proc/cmdline "${BASE_DIR}/proc"
        cp -pRL /proc/swaps "${BASE_DIR}/proc"
        cp -pRL /proc/partitions "${BASE_DIR}/proc"
        cp -pRL /proc/scsi "${BASE_DIR}/proc"
        cp -pRL /proc/sys "${BASE_DIR}/proc"

        cp -pRL /boot "${BASE_DIR}"
        cp -pRL /etc/cron* "${BASE_DIR}/cron/"
        cp -pRL /etc/anacron* "${BASE_DIR}/cron/"
        cp -pRL /var/spool/cron "${BASE_DIR}/cron"
        cp -pRL /var/log "${BASE_DIR}/var_log"

    } 2>> "${BASE_DIR}/error.out"

}

ubuntu_config () {

    cmd_check "lsb_release -a" "${BASE_DIR}/lsb_release_a"
    cmd_check "dpkg -l" "${BASE_DIR}/dpkg_l"

    {
        cp -pRL /etc/network "${BASE_DIR}/etc"
        cp -pRL /etc/modules-load.d/modules.conf "${BASE_DIR}/etc"

    } 2>> "${BASE_DIR}/error.out"
}

network_info () {

    cmd_check "ifconfig -a" "${BASE_DIR}/networking/ifconfig_a"
    cmd_check "arp -a" "${BASE_DIR}/networking/arp_a"
    cmd_check "ip -o link show" "${BASE_DIR}/networking/ip_o_link_show"
    cmd_check "iptables -L" "${BASE_DIR}/networking/iptables_l"
    cmd_check "iptables -L INPUT --line-numbers" "${BASE_DIR}/networking/iptables_l_input"
    cmd_check "netstat -an" "${BASE_DIR}/networking/netstat_an"
    cmd_check "netstat -tan" "${BASE_DIR}/networking/netstat_tan"
    cmd_check "netstat -rn" "${BASE_DIR}/networking/netstat_rn"
    cmd_check "netstat -i" "${BASE_DIR}/networking/netstat_i"
    cmd_check "netstat -tulpn" "${BASE_DIR}/networking/netstat_tulpn"
    cmd_check "brctl show" "${BASE_DIR}/networking/brctl_show"

    egrep -vi 'inter|face' /proc/net/dev |awk '{print $1}' | cut -f1 -d':' |
    while read -r i
    do
        ethtool -i "${i}" &> "${BASE_DIR}/networking/ethtool_i_${i}"
        ethtool "${i}" &> "${BASE_DIR}/networking/ethtool_${i}"
    done

}

nfs_info () {

        cmd_check "rpcinfo -p" "${BASE_DIR}/nfs/rpcinfo_p"
        cmd_check "nfsstat -m" "${BASE_DIR}/nfs/nfsstat_m"
        cmd_check "nfsstat -n" "${BASE_DIR}/nfs/nfsstat_n"
        cmd_check "nfsstat -a" "${BASE_DIR}/nfs/nfsstat_a"
        cmd_check "nfsstat -r" "${BASE_DIR}/nfs/nfsstat_r"
        cmd_check "nfsstat -s" "${BASE_DIR}/nfs/nfsstat_s"
        cmd_check "showmount -e" "${BASE_DIR}/nfs/showmount_e"
        cmd_check "showmount -a" "${BASE_DIR}/nfs/showmount_a"
        cmd_check "exportfs" "${BASE_DIR}/nfs/exportfs"

}

config_info () {

    mkdir "${BASE_DIR}/src"
    cmd_check "ls -laR /lib/security" "${BASE_DIR}/pam/ls_security"
    cmd_check "ls -l /usr/src" "${BASE_DIR}/src/ls_l"

    {
        cp -pRL /etc/sysconfig/docker* "${BASE_DIR}/etc/sysconfig/"
        cp -pRL /etc/modules.conf "${BASE_DIR}/etc"
        cp -pRL /etc/sysctl.conf "${BASE_DIR}/etc"
        cp -pRL /etc/*release "${BASE_DIR}/etc"
        cp -pRL /etc/modprobe.conf "${BASE_DIR}/etc"
        cp -pRL /etc/lvm "${BASE_DIR}/etc/"
        cp -pRL /etc/fstab* "${BASE_DIR}/etc"
        cp -pRL /etc/mtab "${BASE_DIR}/etc"
        cp -pRL /etc/lilo.conf "${BASE_DIR}/etc"
        cp -pRL /etc/grub2.cfg "${BASE_DIR}/etc"
        cp -pRL /etc/sysconfig/network-scripts/* "${BASE_DIR}/etc/sysconfig/network-scripts/"
        cp -pRL /etc/rc* "${BASE_DIR}/etc"
        cp -pRL /etc/host* "${BASE_DIR}/etc"
        cp -pRL /etc/nsswitch.conf "${BASE_DIR}/etc"
        cp -pRL /etc/services "${BASE_DIR}/etc"
        cp -pRL /etc/resolv.conf "${BASE_DIR}/etc"
        cp -pRL /etc/pam.d "${BASE_DIR}/pam"
        cp -pRL /etc/exports "${BASE_DIR}/etc"
        cp -pRL /etc/udev/rules.d/* "${BASE_DIR}/etc/udev/rules.d/"
        cp -pRL /etc/docker "${BASE_DIR}/etc/"

    } 2>> "${BASE_DIR}/error.out"

}

docker_info () {

    mkdir -p "${BASE_DIR}/docker/docker_volumes"
    mkdir "${BASE_DIR}/docker/docker_networks"

    {
        docker ps > "${BASE_DIR}/docker/docker_ps"
        docker ps -a > "${BASE_DIR}/docker/docker_ps_a"
        docker version > "${BASE_DIR}/docker/docker_version"
        dockerd --version > "${BASE_DIR}/docker/dockerd_version"
        docker info > "${BASE_DIR}/docker/docker_info"
        docker images --no-trunc > "${BASE_DIR}/docker/docker_images_notrunc"
        docker images > "${BASE_DIR}/docker/docker_images"
        docker stats --no-stream > "${BASE_DIR}/docker/docker_stats"
        docker volume ls > "${BASE_DIR}/docker/docker_volumes/docker_volume_ls"
        docker network ls > "${BASE_DIR}/docker/docker_networks/docker_network_ls"
        docker network ls --no-trunc > "${BASE_DIR}/docker/docker_networks/docker_network_ls_notrunc"

        cp -pRL /etc/docker/daemon.json "${BASE_DIR}/docker/etc_docker_daemon.json" 
        #cp -pRL /var/lib/docker/containers/ "${BASE_DIR}/var_lib_docker_containers" 

    } 2>> "${BASE_DIR}/error.out"

    docker volume ls 2> /dev/null | grep -v DRIVER |
    while read -r i
    do
        volname="$( echo "${i}" | awk '{print $2}' )"
        docker volume inspect "${volname}" &> "${BASE_DIR}/docker/docker_volumes/docker_volume_inspect_${volname}"
    done

    docker network ls --no-trunc 2> /dev/null | grep -v SCOPE |
    while read -r i
    do
        netname="$( echo "${i}" | awk '{print $2}' )"
        netid="$( echo "${i}" | awk '{print $1}' )"
        docker network inspect "$netid" &> "${BASE_DIR}/docker/docker_networks/docker_network_inspect_${netname}"
    done

    docker ps -a 2> /dev/null |
    while read -r i
    do
        fname="$( echo "${i}" | awk '{print $2}' | cut -f2 -d'/' | cut -f1 -d':' )"
        contid="$( echo "${i}" | awk '{print $1}' )"
        imagename="$( echo "${i}" |awk '{print $2}' | cut -f1 -d':' )"
        imageid="$( docker images | grep "${imagename}" | awk '{print $3}' )"

        mkdir -p "${BASE_DIR}/docker/containers/${fname}"
        docker inspect -s "${contid}" &> "${BASE_DIR}/docker/containers/${fname}/docker_inspect_s"
        docker top "${contid}" &> "${BASE_DIR}/docker/containers/${fname}/docker_top"
        docker top "${contid}" -Telf  &> "${BASE_DIR}/docker/containers/${fname}/docker_top_Telf"

        docker logs "${contid}" &> "${BASE_DIR}/docker/containers/${fname}/docker_logs"
        docker history "${imageid}" &> "${BASE_DIR}/docker/containers/${fname}/docker_history"
        docker history --no-trunc "${imageid}" &> "${BASE_DIR}/docker/containers/${fname}/docker_history_notrunc"
        docker inspect "${imageid}" &> "${BASE_DIR}/docker/containers/${fname}/docker_image_inspect"
    done

}

docker_swarm () {

    mkdir "${BASE_DIR}/docker/swarm"
    docker service ls &> "${BASE_DIR}/docker/swarm/docker_service_ls"
    docker service ls | grep -v 'REPLICAS' | awk '{print $2}' |
    while read -r i
    do
        docker service ps "${i}" &> "${BASE_DIR}/docker/swarm/docker_service_ps_${i}"
        docker service inspect "${i}" &> "${BASE_DIR}/docker/swarm/docker_service_inspect_${i}"
        docker service inspect "${i}" --pretty &> "${BASE_DIR}/docker/swarm/docker_service_inspect_pretty_${i}"
    done

    if [ "$( docker info 2> /dev/null | grep 'Is Manager' | grep -q 'true' ; echo $? )" == "0" ];
    then
        docker node ls &> "${BASE_DIR}/docker/swarm/docker_node_ls"
        docker node ls | grep -v 'MANAGER' | awk '{print $2,$3}' | cut -f2 -d'*' | awk '{print $1}' |
        while read -r i
        do
            docker node inspect "${i}" &> "${BASE_DIR}/docker/swarm/docker_node_inspect_${i}"
            docker node inspect "${i}" --pretty &> "${BASE_DIR}/docker/swarm/docker_node_inspect_pretty_${i}"
            docker node ps "${i}" &> "${BASE_DIR}/docker/swarm/docker_node_ps_${i}"
        done
    fi

}

kubernetes () {

    mkdir "${KUBE_HOME}"
    touch "${KUBE_HOME}/error.out"
    cmd_check "systemctl status -l flanneld" "${BASE_DIR}/systemctl_status_l_flanneld"

    {

        cp -pRL /etc/sysconfig/flanneld "${BASE_DIR}/etc/sysconfig/" 
        cp -pRL /etc/kubernetes "${BASE_DIR}/etc/" 


    } 2>> "${BASE_DIR}/error.out"

    if (( "$( rpm -qa 2>/dev/null | grep -qi 'kubernetes-master' ; echo $? )" == "0" ||
        "$(dpkg -l 2>/dev/null | grep -qi 'kubernetes-master' ; echo $? )" == "0" ));
    then
        touch "${KUBE_HOME}/THIS_IS_A_KUBERNETES_MASTER_NODE"
        kubernetes_master
    else
        touch "${KUBE_HOME}/THIS_IS_A_KUBERNETES_SLAVE_NODE"
        kubernetes_slave
    fi

}

kubernetes_master () {

    mkdir -p "${KUBE_HOME}/etc/etcd"
    cp -pRL /etc/etcd/etcd.conf "${KUBE_HOME}/etc/etcd/" 2>> "${BASE_DIR}/error.out"

    cmd_check "systemctl status -l etcd" "${KUBE_HOME}/systemctl_status_l_etcd"
    cmd_check "systemctl status -l kube-apiserver" "${KUBE_HOME}/systemctl_status_l_kube_apiserver"
    cmd_check "systemctl status -l kube-controller-manager" "${KUBE_HOME}/systemctl_status_l_kube_controller_manager"
    cmd_check "systemctl status -l kube-scheduler" "${KUBE_HOME}/systemctl_status_l_kube_scheduler"

    cmd_check "kubectl version --short=true"  "${KUBE_HOME}/kubectl_version_short"
    cmd_check "kubectl version" "${KUBE_HOME}/kubectl_version"
    cmd_check "kubectl cluster-info dump" "${KUBE_HOME}/kubectl_cluster_info_dump"
    cmd_check "kubectl api-versions" "${KUBE_HOME}/kubectl_api-versions"
    cmd_check "kubectl config get-clusters" "${KUBE_HOME}/kubectl_config_get-clusters"
    cmd_check "kubectl config get-contexts" "${KUBE_HOME}/kubectl_config_get-contexts"
    cmd_check "kubectl config view" "${KUBE_HOME}/kubectl_config_view"
    cmd_check "kube-controller-manager --version" "${KUBE_HOME}/kube-controller-manager_version"
    cmd_check "kube-apiserver --version" "${KUBE_HOME}/kube-apiserver_version"
    cmd_check "kube-scheduler --version" "${KUBE_HOME}/kube-scheduler_version"

    IFS=$'\n'

    for p in $( kubectl get pod --all-namespaces -o wide 2> /dev/null | grep -v 'NAME' )
    do
        pod_name="$( echo "${p}" | awk -F '[[:space:]]+|-[0-9]' '{print $2}' )"
        name_space="$( echo "${p}" | awk '{print $1}' )"
        kubectl log "${pod_name}" -v=9 --namespace="$name_space" &> "${KUBE_HOME}/kubectl_log_${pod_name}"
    done

    IFS=

    # kubectl describe -h | sed -e '1,/Valid/ d' | sed -e '/Examples/,$d' | awk '{print $2}'
    descr_param=(certificatesigningrequest configmap cronjob daemonset deployment endpoints horizontalpodautoscaler ingress job limitrange namespace networkpolicy node persistentvolume persistentvolumeclaim pod poddisruptionbudget replicaset replicationcontroller resourcequota secret securitycontextconstraints service serviceaccount statefulset storageclass)

    get_param=(certificatesigningrequest cluster clusterrole clusterrolebinding componentstatus configmap cronjob daemonset deployment endpoints event horizontalpodautoscaler ingress job limitrange namespace networkpolicy node persistentvolume persistentvolumeclaim pod poddisruptionbudget podsecuritypolicy podtemplate replicaset replicationcontroller resourcequota role rolebinding secret securitycontextconstraints service serviceaccount statefulset status storageclass thirdpartyresource thirdpartyresourcedata)

    for j in "${descr_param[@]}"
    do
        IFS=$'\n'
        if [ "$( kubectl get --all-namespaces "${j}" 2> /dev/null | grep -cv 'NAME' )" -gt '0' ];
        then
            mkdir "${KUBE_HOME}/${j}"
            if [[ ! "${j}" =~ (componentstatus|namespace|node) ]];
            then
                for i in $(kubectl get "${j}" --all-namespaces -o wide 2> /dev/null| grep -v ' NAME' )
                do
                    given_name="$( echo "${i}" | awk '{print $2}' )"
                    name_space="$( echo "${i}" | awk '{print $1}' )"
                    kubectl describe "${j}/${given_name} --namespace=${name_space}" &> "${KUBE_HOME}/${j}/kubectl_describe_${j}_${given_name}"
                done
            fi
        fi
        IFS=

    done

    for j in "${get_param[@]}"
    do
        IFS=$'\n'
        if [[ ! "${j}" =~ (componentstatus|namespace|node) ]];
        then
            if [ "$( kubectl get "${j}" -o wide --all-namespaces &> /dev/null ; echo $? )" == '0' ] &&
               [ "$( kubectl get "${j}" -o wide --all-namespaces 2> /dev/null  | grep -cv 'NAME' )" -gt '0' ];
            then
                kubectl get "${j}" -o wide --all-namespaces &> "${KUBE_HOME}/kubectl_get_${j}"
            fi
        else
            kubectl get "${j}" -o wide &> "${KUBE_HOME}/kubectl_get_${j}"
        fi
        IFS=
    done

}

kubernetes_slave () {

    cmd_check "systemctl status -l kubelet" "${KUBE_HOME}/systemctl_status_l_kubelet"
    cmd_check "systemctl status -l kube-proxy" "${KUBE_HOME}/systemctl_status_l_kube_proxy"
    cmd_check "kubelet --version" "${KUBE_HOME}/kubelet_version"
    cmd_check "kube-proxy --version" "${KUBE_HOME}/kube-proxy_version"

}

common_logs () {

    KUBE_HOME="${BASE_DIR}/kubernetes"

    echo -e "\nMaking Requisite Directory structures under '$user_path_full' "
    dir_structure

    echo -e "\nGathering Server related information ......................"
    server_info

    echo -e "\nGathering Network related information ....................."
    network_info
    nfs_info

    echo -e "\nGathering Configuration information ......................."
    config_info
    ubuntu_config


    if (( "$( rpm -qa 2> /dev/null | grep -q 'docker' ; echo $? )" == "0"  &&
          "$( docker ps -a &> /dev/null ; echo $?)" == "0" )) ||
       (( "$(uname -v | grep -q Ubuntu ; echo $?)" == "0"  &&
          "$( docker ps -a &> /dev/null ; echo $?)" == "0" )) ;
    then
        echo -e "\nGathering Docker related information ......................"
        docker_info

        if [ "$( docker info 2> /dev/null | grep 'Swarm' | grep -q 'inactive' ; echo $? )" == "1" ];
        then
            echo -e "\nGathering Docker-Swarm related information ................"
            docker_swarm
        fi
    else
        echo -e "\n\n************  SKIPPING DOCKER AND DOCKER SWARM RELATED INFORMATION  ***********\n"\
        "****EITHER DOCKER DAEMON IS NOT RUNNING OR DOCKER IS NOT INSTALLED AT ALL****\n" &>> "${BASE_DIR}/error.out"
    fi

    if (( "$( rpm -qa 2> /dev/null | grep -qi 'kubernetes' ; echo $? )" == "0"  ||
          "$(dpkg -l 2>/dev/null | grep -qi 'kubernetes' ; echo $?)" == "0"  ));
    then
        echo -e "\nGathering Kubernetes related information .................."
        kubernetes
    fi

}


########################
#     Main Program     #
########################


DATE="$(date +%s)"

trap 'rc=$?; trap "" EXIT; sig_trap $rc; exit $rc' INT TERM QUIT HUP

if [ "$#" != "0" ];
then
    echo "Usage: $0"
else
    if (( "$(id -u)" != "0" ));
    then
        echo -e "\nThis script should be run as root\n"
        exit
    fi
    echo -e "\nCollecting logs ...........................................\n"
    echo -e "\nThis should take less than 5 minutes ......................\n\n\n"

    log_vers="$( grep -m1 'LINUX LOGGATHER VERSION' "$0" )"

    echo -e "Typical space requirement is 500 Mb\n"
    read -p 'Enter the directory path to store loggather data : ' user_path
    if [ "${user_path_full}" == "" ];
    then
        user_path="."
    fi
    user_path_full="$(readlink -f "${user_path}")"
    if [ -d "${user_path_full}" ] ;
    then
        if (( "$(df -m "${user_path_full}" | grep -v 'Available' | awk '{print $4}' )" > " 500" )) ;
        then
            BASE_DIR="${user_path_full}/logs_$(hostname)_${DATE}"
        else
            echo -e "\n\n${user_path_full} doesn't have 500Mb of space... exiting ..\n"
            exit
        fi
    else
        while true;
        do
            read -p "Directory provided \"${user_path_full}\" doesn't exist... Create it ? (y/n): " create_dir
            if [ "${create_dir}" == "y" ] ;
            then
                mkdir "${user_path_full}"
                if (( "$(df -m "${user_path_full}" | grep -v 'Available' | awk '{print $4}' )" > " 500" )) ;
                then
                    break
                else
                    echo -e "\n\n${user_path_full} doesn't have 500Mb of space... exiting ..\n"
                    rmdir "${user_path_full}"
                    exit
                fi
            elif [ "${create_dir}" == "n" ];
            then
                echo "Exiting ..."
                exit
            else
                echo -e "Please enter y or n\n"
            fi
        done
        BASE_DIR="${user_path_full}/logs_$(hostname)_${DATE}"
    fi

    mkdir "${BASE_DIR}"
    echo -e "\n${log_vers}" &> "${BASE_DIR}/loggather_summary_report"
    echo -e "\nCustomer Ran the Loggather at : $(date)\n" &>> "${BASE_DIR}/loggather_summary_report"

    common_logs

    cd "${user_path_full}"
    echo -e "\nCreating a zipped tar bundle ..............................\n"
    tar czf "${user_path_full}/logs_$(hostname)_${DATE}.tar.gz" "logs_$(hostname)_$DATE" 2> /dev/null
    rm -rf "${BASE_DIR}"

    echo -e "\nLogs are located at : ${user_path_full}/logs_$(hostname)_${DATE}.tar.gz \n"

fi
