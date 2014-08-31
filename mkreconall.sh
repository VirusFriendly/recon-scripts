#!/bin/sh
echo "#Quick and Dirty Recon" > recon_all.rc
echo "#Look ma no hands!" >> recon_all.rc
echo "#Just create a new workspace and set the domain and launch recon-ng with this script" >> recon_all.rc
cat recon_hosts.rc >> recon_all.rc
cat recon_ips.rc >> recon_all.rc
cat recon_contacts.rc >> recon_all.rc
cat recon_reports.rc >> recon_all.rc
echo exit >> recon_all.rc
