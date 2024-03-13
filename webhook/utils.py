from control.utils import mask_card


def get_notification_data(notification_data):
    if 'tarjeta' in notification_data:
        notification_data['tarjeta'] = mask_card(notification_data['tarjeta'])
    if 'Tarjeta' in notification_data:
        notification_data['Tarjeta'] = mask_card(notification_data['Tarjeta'])
    return notification_data