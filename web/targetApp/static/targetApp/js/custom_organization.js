function delete_organization(id) {
    const delAPI = "../delete/organization/"+id;
    swal.queue([{
        title: 'Are you sure you want to delete?',
        text: "You won't be able to revert this!",
        type: 'warning',
        showCancelButton: true,
        confirmButtonText: 'Delete',
        padding: '2em',
        showLoaderOnConfirm: true,
        preConfirm: function() {
          return fetch(delAPI, {
	            method: 'POST',
                credentials: "same-origin",
                headers: {
                    "X-CSRFToken": getCookie("csrftoken")
                }
            })
            .then(function (response) {
                return response.json();
            })
            .then(function(data) {
                // TODO Look for better way
               return location.reload();
            })
            .catch(function() {
              swal.insertQueueStep({
                type: 'error',
                title: 'Oops! Unable to delete the target!'
              })
            })
        }
    }])
}


function download_report(org_id) {
    const url = `/target/generate_report/organization/${org_id}`

    Swal.fire({
        title: "Generating report..."
    });
    swal.showLoading();
    fetch(url, {
        method: 'GET',
        credentials: "same-origin",
        headers: {
            "X-CSRFToken": getCookie("csrftoken"),
            'Content-Type': 'application/json'
        },
    }).then(response => response.json()).then(function(response) {
        if (response.status == "generation success") {
            swal.close();
            window.open(`/target/download_pdf/organization/${org_id}`) // To download
            window.location.replace(`/target/list/organization`) // To show success message
        } else if (response.status == "generation failed") {
            swal.close();
            window.open(`/target/download_error_logs/organization/${org_id}`) // To download
            window.location.replace(`/target/list/organization`) // To show error message
        } else {
            window.location.replace(`/target/list/organization`) // To show error message
        }
    });
}
