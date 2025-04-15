from ioc.ioc_checker import (
    IOCChecker,
    update_ioc_list_from_feodo,
    update_ioc_list_from_threatfox,
    update_ioc_list_from_openphish,
    clear_ioc_list
)

def handle_update_all_iocs(ioc_status_label):
    clear_ioc_list()
    messages = []
    success = True

    for updater in [
        update_ioc_list_from_feodo,
        update_ioc_list_from_threatfox,
        update_ioc_list_from_openphish
    ]:
        ok, msg = updater()
        messages.append(msg)
        if not ok:
            success = False

    ioc_status_label.config(text="\n".join(messages))

    if success:
        global ioc
        ioc = IOCChecker()
