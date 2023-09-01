from reNgine.settings import BASE_DIR, RENGINE_HOME
import validators
import csv
import io
import os
import requests
import threading
import jinja2

from datetime import timedelta
from operator import and_, or_
from functools import reduce
from django import http
from django.shortcuts import render, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from django.db.models import Count, Q
from django.utils.safestring import mark_safe
from weasyprint import HTML

from targetApp.models import *
from startScan.models import *
from scanEngine.models import *
from targetApp.forms import *
from reNgine.common_func import *

def create_dir(path):
    if not os.path.isdir(path):
        # automatically create the folder (can be edited by user)
        # https://stackoverflow.com/questions/47618490/python-create-a-directory-with-777-permissions
        os.umask(0)
        os.makedirs(path, mode=0o777)


def index(request):
    # TODO bring default target page
    return render(request, 'target/index.html')


def add_target(request):
    add_target_form = AddTargetForm(request.POST or None)
    if request.method == "POST":
        if 'add-single-target' in request.POST and add_target_form.is_valid():
            Domain.objects.create(
                **add_target_form.cleaned_data,
                insert_date=timezone.now())
            messages.add_message(
                request,
                messages.INFO,
                'Target domain ' +
                add_target_form.cleaned_data['name'] +
                ' added successfully')
            if 'fetch_whois_checkbox' in request.POST and request.POST['fetch_whois_checkbox'] == 'on':
                thread = threading.Thread(
                    target=get_whois,
                    args=[add_target_form.cleaned_data['name'], True, False]
                )
                thread.setDaemon(True)
                thread.start()
            return http.HttpResponseRedirect(reverse('list_target'))
        if 'add-ip-target' in request.POST:
            domains = request.POST.getlist('resolved_ip_domains')
            description = request.POST['targetDescription'] if 'targetDescription' in request.POST else ''
            ip_address_cidr = request.POST['ip_address'] if 'ip_address' in request.POST else ''
            h1_team_handle = request.POST['targetH1TeamHandle'] if 'targetH1TeamHandle' in request.POST else None
            added_target_count = 0
            for domain in domains:
                if not Domain.objects.filter(
                        name=domain).exists() and validators.domain(domain):
                    Domain.objects.create(
                        name=domain,
                        description=description,
                        h1_team_handle=h1_team_handle,
                        ip_address_cidr=ip_address_cidr,
                        insert_date=timezone.now())
                    added_target_count += 1
            if added_target_count:
                messages.add_message(request, messages.SUCCESS, str(
                    added_target_count) + ' targets added successfully!')
                return http.HttpResponseRedirect(reverse('list_target'))
            else:
                messages.add_message(
                    request,
                    messages.ERROR,
                    'Oops! Could not import any targets, either targets already exists or is not a valid target.')
                return http.HttpResponseRedirect(reverse('add_target'))
        elif 'add-multiple-targets' in request.POST:
            bulk_targets = [target.rstrip()
                            for target in request.POST['addTargets'].split('\n')]
            bulk_targets = [target for target in bulk_targets if target]
            description = request.POST['targetDescription'] if 'targetDescription' in request.POST else ''
            h1_team_handle = request.POST['targetH1TeamHandle'] if 'targetH1TeamHandle' in request.POST else None
            target_count = 0
            for target in bulk_targets:
                if not Domain.objects.filter(
                        name=target).exists() and validators.domain(target):
                    Domain.objects.create(
                        name=target.rstrip("\n"),
                        description=description,
                        h1_team_handle=h1_team_handle,
                        insert_date=timezone.now())
                    target_count += 1
            if target_count:
                messages.add_message(request, messages.SUCCESS, str(
                    target_count) + ' targets added successfully!')
                return http.HttpResponseRedirect(reverse('list_target'))
            else:
                messages.add_message(
                    request,
                    messages.ERROR,
                    'Oops! Could not import any targets, either targets already exists or is not a valid target.')
                return http.HttpResponseRedirect(reverse('add_target'))
        elif 'import-txt-target' in request.POST or 'import-csv-target' in request.POST:
            if 'txtFile' in request.FILES:
                txt_file = request.FILES['txtFile']
                if txt_file.content_type == 'text/plain':
                    target_count = 0
                    txt_content = txt_file.read().decode('UTF-8')
                    io_string = io.StringIO(txt_content)
                    for target in io_string:
                        target_domain = target.rstrip("\n").rstrip("\r")
                        if not Domain.objects.filter(
                                name=target_domain).exists() and validators.domain(target_domain):
                            Domain.objects.create(
                                name=target_domain,
                                insert_date=timezone.now())
                            target_count += 1
                    if target_count:
                        messages.add_message(request, messages.SUCCESS, str(
                            target_count) + ' targets added successfully!')
                    else:
                        messages.add_message(
                            request,
                            messages.ERROR,
                            'Error importing targets, either targets already exist or CSV file is not valid.')
                        return http.HttpResponseRedirect(reverse('add_target'))
                else:
                    messages.add_message(
                        request, messages.ERROR, 'Invalid File type!')
                    return http.HttpResponseRedirect(reverse('add_target'))
            elif 'csvFile' in request.FILES:
                csv_file = request.FILES['csvFile']
                if csv_file.content_type == 'text/csv' or csv_file.name.split('.')[1]:
                    target_count = 0
                    csv_content = csv_file.read().decode('UTF-8')
                    io_string = io.StringIO(csv_content)
                    for column in csv.reader(io_string, delimiter=','):
                        target_domain = column[0]
                        description = None if len(column) == 1 else column[1]
                        if not Domain.objects.filter(
                                name=target_domain).exists() and validators.domain(
                                target_domain):
                            Domain.objects.create(
                                name=target_domain,
                                description=description,
                                insert_date=timezone.now())
                            target_count += 1
                    if target_count:
                        messages.add_message(request, messages.SUCCESS, str(
                            target_count) + ' targets added successfully!')
                    else:
                        messages.add_message(
                            request,
                            messages.ERROR,
                            'Error importing targets, either targets already exist or CSV file is not valid.')
                        return http.HttpResponseRedirect(reverse('add_target'))
                else:
                    messages.add_message(
                        request, messages.ERROR, 'Invalid File type!')
                    return http.HttpResponseRedirect(reverse('add_target'))
            return http.HttpResponseRedirect(reverse('list_target'))
        elif "add-internal-target" in request.POST:
            name = request.POST["internal_name"] if "internal_name" in request.POST else ""
            ip_address = request.POST["internal_ip_address"] if "internal_ip_address" in request.POST else ""
            description = request.POST["internal_target_description"] if "internal_target_description" in request.POST else ""

            if not name or not ip_address:
                messages.add_message(request, messages.ERROR, 'Internal target without name or ip address')
            elif not Domain.objects.filter(name=name).exists():

                cert_dir = f"{RENGINE_HOME}/user-certs/{name}"
                create_dir(cert_dir)

                Domain.objects.create(
                    name=name,
                    description=description,
                    ip_address_cidr=ip_address,
                    is_internal=True,
                    insert_date=timezone.now(),
                )
                messages.add_message(request, messages.SUCCESS, 'Internal target added successfully!')
            else:
                messages.add_message(request, messages.WARNING, 'Internal target already added!')
            return http.HttpResponseRedirect(reverse('list_target'))

    context = {
        "add_target_li": "active",
        "target_data_active": "active",
        'form': add_target_form}
    return render(request, 'target/add.html', context)

def list_target(request):
    context = {
        'list_target_li': 'active',
        'target_data_active': 'active'
    }
    return render(request, 'target/list.html', context)


def delete_target(request, id):
    obj = get_object_or_404(Domain, id=id)
    if request.method == "POST":
        os.system(
            'rm -rf ' +
            settings.TOOL_LOCATION +
            'scan_results/' +
            obj.name + '*')
        obj.delete()
        responseData = {'status': 'true'}
        messages.add_message(
            request,
            messages.INFO,
            'Domain successfully deleted!')
    else:
        responseData = {'status': 'false'}
        messages.add_message(
            request,
            messages.ERROR,
            'Oops! Domain could not be deleted!')
    return http.JsonResponse(responseData)


def delete_targets(request):
    context = {}
    if request.method == "POST":
        list_of_domains = []
        for key, value in request.POST.items():
            if key != "list_target_table_length" and key != "csrfmiddlewaretoken":
                Domain.objects.filter(id=value).delete()
        messages.add_message(
            request,
            messages.INFO,
            'Targets deleted!')
    return http.HttpResponseRedirect(reverse('list_target'))


def update_target(request, id):
    domain = get_object_or_404(Domain, id=id)
    form = UpdateTargetForm()
    if request.method == "POST":
        form = UpdateTargetForm(request.POST, instance=domain)
        if form.is_valid():
            form.save()
            messages.add_message(
                request,
                messages.INFO,
                'Domain {} modified!'.format(domain.name))
            return http.HttpResponseRedirect(reverse('list_target'))
    else:
        form.set_value(domain.name, domain.description, domain.h1_team_handle)
    context = {
        'list_target_li': 'active',
        'target_data_active': 'active',
        "domain": domain,
        "form": form}
    return render(request, 'target/update.html', context)

def target_summary(request, id):
    context = {}
    target = get_object_or_404(Domain, id=id)
    context['target'] = target
    context['scan_count'] = ScanHistory.objects.filter(
        domain_id=id).count()
    last_week = timezone.now() - timedelta(days=7)
    context['this_week_scan_count'] = ScanHistory.objects.filter(
        domain_id=id, start_scan_date__gte=last_week).count()
    subdomains = Subdomain.objects.filter(
        target_domain__id=id).values('name').distinct()
    endpoints = EndPoint.objects.filter(
        target_domain__id=id).values('http_url').distinct()

    vulnerabilities = Vulnerability.objects.filter(target_domain__id=id)
    vulnerability_count = vulnerabilities.count()
    context['subdomain_count'] = subdomains.count()
    context['alive_count'] = subdomains.filter(http_status__exact=200).count()
    context['endpoint_count'] = endpoints.count()
    context['endpoint_alive_count'] = endpoints.filter(http_status__exact=200).count()

    context['scan_engines'] = EngineType.objects.all()

    unknown_count = vulnerabilities.filter(severity=-1).count()
    info_count = vulnerabilities.filter(severity=0).count()
    low_count = vulnerabilities.filter(severity=1).count()
    medium_count = vulnerabilities.filter(severity=2).count()
    high_count = vulnerabilities.filter(severity=3).count()
    critical_count = vulnerabilities.filter(severity=4).count()

    context['unknown_count'] = unknown_count
    context['info_count'] = info_count
    context['low_count'] = low_count
    context['medium_count'] = medium_count
    context['high_count'] = high_count
    context['critical_count'] = critical_count

    context['total_vul_ignore_info_count'] = low_count + \
        medium_count + high_count + critical_count

    context['most_common_vulnerability'] = Vulnerability.objects.exclude(severity=0).filter(target_domain__id=id).values("name", "severity").annotate(count=Count('name')).order_by("-count")[:10]

    emails = Email.objects.filter(emails__in=ScanHistory.objects.filter(domain__id=id).distinct())

    context['exposed_count'] = emails.exclude(password__isnull=True).count()

    context['email_count'] = emails.count()

    context['employees_count'] = Employee.objects.filter(
        employees__in=ScanHistory.objects.filter(id=id)).count()

    context['recent_scans'] = ScanHistory.objects.filter(
        domain=id).order_by('-start_scan_date')[:4]

    context['vulnerability_count'] = vulnerability_count

    context['vulnerability_list'] = Vulnerability.objects.filter(
        target_domain__id=id).order_by('-severity').all()[:30]

    context['http_status_breakdown'] = Subdomain.objects.filter(target_domain=id).exclude(http_status=0).values('http_status').annotate(Count('http_status'))

    context['most_common_cve'] = CveId.objects.filter(cve_ids__in=Vulnerability.objects.filter(target_domain__id=id)).annotate(nused=Count('cve_ids')).order_by('-nused').values('name', 'nused')[:7]
    context['most_common_cwe'] = CweId.objects.filter(cwe_ids__in=Vulnerability.objects.filter(target_domain__id=id)).annotate(nused=Count('cwe_ids')).order_by('-nused').values('name', 'nused')[:7]
    context['most_common_tags'] = VulnerabilityTags.objects.filter(vuln_tags__in=Vulnerability.objects.filter(target_domain__id=id)).annotate(nused=Count('vuln_tags')).order_by('-nused').values('name', 'nused')[:7]

    context['asset_countries'] = CountryISO.objects.filter(ipaddress__in=IpAddress.objects.filter(ip_addresses__in=Subdomain.objects.filter(target_domain__id=id))).annotate(count=Count('iso')).order_by('-count')

    return render(request, 'target/summary.html', context)

def upload_org_template(template_file, org_name):
    # Write the new latex_template

    try:
        template_dir = os.path.join(RENGINE_HOME, "latex_templates", org_name)
        new_template = os.path.join(template_dir, "template.tex.jinja")

        create_dir(template_dir)

        with open(new_template, 'wb+') as destination:
            for chunk in template_file.chunks():
                destination.write(chunk)  

        return True

    except Exception:
        return False

def add_organization(request):
    form = AddOrganizationForm(request.POST or None)
    if request.method == "POST":
        print(form.errors)
        if form.is_valid():
            organization = Organization.objects.create(
                name=form.cleaned_data['name'],
                description=form.cleaned_data['description'],
                insert_date=timezone.now())
            for domain_id in request.POST.getlist("domains"):
                domain = Domain.objects.get(id=domain_id)
                organization.domains.add(domain)
            messages.add_message(
                request,
                messages.INFO,
                'Organization ' +
                form.cleaned_data['name'] +
                ' added successfully')

            template_dir = f"{RENGINE_HOME}/latex_templates/{organization.name}"
            create_dir(template_dir)

            if 'latex_template' in request.FILES.keys():
                upload_org_template(request.FILES["latex_template"], organization.name)

            return http.HttpResponseRedirect(reverse('list_organization'))
    context = {
        "organization_active": "active",
        "form": form
    }
    return render(request, 'organization/add.html', context)

def list_organization(request):
    organizations = Organization.objects.all().order_by('-insert_date')
    statuses = Organization.Status.choices
    context = {
        'organization_active': 'active',
        'organizations': organizations,
        'statuses' : statuses,
    }
    return render(request, 'organization/list.html', context)

def delete_organization(request, id):
    if request.method == "POST":
        obj = get_object_or_404(Organization, id=id)
        obj.delete()
        responseData = {'status': 'true'}
        messages.add_message(
            request,
            messages.INFO,
            'Organization successfully deleted!')
    else:
        responseData = {'status': 'false'}
        messages.add_message(
            request,
            messages.ERROR,
            'Oops! Organization could not be deleted!')
    return http.JsonResponse(responseData)

def update_organization(request, id):
    organization = get_object_or_404(Organization, id=id)
    form = UpdateOrganizationForm()
    if request.method == "POST":
        print(request.POST.getlist("domains"))
        form = UpdateOrganizationForm(request.POST, instance=organization)
        if form.is_valid():
            organization_obj = Organization.objects.filter(
                id=id
            )

            for domain in organization.get_domains():
                organization.domains.remove(domain)

            organization_obj.update(
                name=form.cleaned_data['name'],
                description=form.cleaned_data['description'],
            )
            for domain_id in request.POST.getlist("domains"):
                domain = Domain.objects.get(id=domain_id)
                organization.domains.add(domain)

            if 'latex_template' in request.FILES.keys():
                upload_org_template(request.FILES["latex_template"], organization.name)

            messages.add_message(
                request,
                messages.INFO,
                'Organization {} modified!'.format(organization.name))
            return http.HttpResponseRedirect(reverse('list_organization'))
    else:
        domain_list = organization.get_domains().values_list('id', flat=True)
        domain_list = [str(id) for id in domain_list]
        form.set_value(organization.name, organization.description)
    context = {
        'list_organization_li': 'active',
        'organization_data_active': 'true',
        "organization": organization,
        "domain_list": mark_safe(domain_list),
        "form": form
    }
    return render(request, 'organization/update.html', context)


def update_testing_status(request, id):
    if request.method == "POST":
        try:
            organization = Organization.objects.filter(id=id)
            body = json.loads(request.body)
            status = body["testing_status"]
            organization.update(status = status)
            messages.add_message(
                    request,
                    messages.INFO,
                    'Status updated for {}!'.format(organization.get().name))
            responseData = {'status': 'true'}
        except Exception:
            messages.add_message(
                    request,
                    messages.ERROR,
                    'Failed to update status!')
            responseData = {'status': 'false'}
        return http.JsonResponse(responseData)

def jinja_to_tex(filename, folder, id):
    organization = Organization.objects.get(id=id)

    domains = []
    for d in organization.get_domains():
        domain = {}
        domain["name"] = d.name
        domain["ip"] = d.ip_address_cidr
        domain["description"] = d.description
        domain["is_internal"] = d.is_internal
        # domain["domain_ip"] = d.domain_info.ip_address
        # print(d.domain_info.ip_address)

        domain["vulnerabilities"] = Vulnerability.objects.filter(target_domain=d).order_by('-severity')
        if d.is_internal:
            domain["internal_ips"] = InternalIp.objects.filter(target_domain=d)

        all_subs = Subdomain.objects.filter(target_domain=d)
        subdomains = []
        for sub in all_subs:
            subdomain = {}
            subdomain["name"] = sub.name
            subdomain["page_title"] = sub.page_title
            subdomain["content_type"] = sub.content_type
            subdomains.append(subdomain)

        domain["subdomains"] = subdomains

        domains.append(domain)


    # Convert the jinja template to tex file
    latex_jinja_env = jinja2.Environment(
        loader = jinja2.FileSystemLoader(folder),
        trim_blocks = True,
        lstrip_blocks = True,
        autoescape = False,
    )

    try:
        template = latex_jinja_env.get_template(filename)
    except Exception as e:
        message = "Failed to convert to latex : " + str(e)
        return message

    try:
        with open(f"{folder}/{filename[:-6]}", "w") as f:
            f.write(template.render(
                org_name = organization.name,
                org_desc = organization.description,
                org_creation = organization.insert_date,
                org_status = organization.get_status_display(),
                domains = domains,
            ))
    except Exception as e:
        message = "Failed to render latex file : " + str(e)
        return message

    return "OK"



def generate_organization_report(request, id):
    if request.method == "GET":
        responseData = {'status': 'error'} # by default

        organization = Organization.objects.get(id=id)

        org_name = organization.name

        output_dir = os.path.join(RENGINE_HOME, "latex_templates", org_name)
        tex_file = os.path.join(output_dir, "template.tex")

        if not os.path.isdir(output_dir):
            messages.error(request, f"Error: template folder not found '{output_dir}'")
            return http.JsonResponse(responseData)

        if len(os.listdir(output_dir)) == 0:
            messages.error(request, f"Error: template folder empty '{output_dir}'. Add a tex jinja template file !")
            return http.JsonResponse(responseData)

        # explore recursively to get all the tex-jinja2 files
        for currentpath, folders, files in os.walk(output_dir):
            for file in files:
                if file.endswith(".tex.jinja"):
                    status = jinja_to_tex(file, currentpath, id)
                    if status != "OK":
                        messages.error(request, status)
                        return http.JsonResponse(responseData)

        process = subprocess.run(["latexmk", "-pdf", "-bibtex", f"-outdir={output_dir}", tex_file], capture_output=True)
        if process.returncode != 0:
            if process.returncode == 11:
                message = f"Could not find the template.tex.jinja file in '{output_dir}'"
                messages.error(request, message)
            else:
                responseData = {'status': 'generation failed'}
                messages.error(request, 'Failed to generate the PDF ! (Read the error log file)')
                return http.JsonResponse(responseData)


        else:
            subprocess.run(["latexmk", "-c", f"-outdir={output_dir}", tex_file])

            messages.info(request, "Report successfully generated")
            responseData = {'status': 'generation success'}
            return http.JsonResponse(responseData)

        return http.JsonResponse(responseData)

def download_report_pdf(request, id):
    if request.method == "GET":
        organization = Organization.objects.get(id=id)

        org_name = organization.name

        output_dir = os.path.join(RENGINE_HOME, "latex_templates", org_name)

        try:
            pdf = open(f"{output_dir}/template.pdf", 'rb')
            return http.FileResponse(pdf, as_attachment=True, filename=f"Report-{org_name}.pdf")

        except Exception:
            messages.error(request, 'Failed to read the generated PDF !')

        return http.HttpResponseRedirect(reverse('list_organization'))

def download_error_logs(request, id):
    if request.method == "GET":
        organization = Organization.objects.get(id=id)

        org_name = organization.name

        output_dir = os.path.join(RENGINE_HOME, "latex_templates", org_name)

        try:
            log = open(f"{output_dir}/template.log", 'rb')
            return http.FileResponse(log, as_attachment=False, filename=f"Errors-{org_name}.log")

        except Exception :
            messages.error(request, "Failed to get error logs !")

        return http.HttpResponseRedirect(reverse('list_organization'))

def download_example_template(request):
    path = os.path.join(RENGINE_HOME, "latex_templates/example_template.tex.jinja")
    return http.FileResponse(open(path, 'rb'), as_attachment=False, filename=f"template.tex.jinja")
