from rest_framework.exceptions import ParseError
from rest_framework.permissions import IsAuthenticated

from common.views import CustomViewSet
from users.permissions import IsVerified, IsOperator


class ControlApiView(CustomViewSet):
    permission_classes = (IsAuthenticated, IsVerified, IsOperator)
    http_method_names = ['post', 'options', 'head']

    def control_action(self, request, control_function, name_control_function):
        response_message = ''
        response_data = dict()
        response_status = 200
        try:
            response_message, response_data, response_status = control_function(request)
            if 'RSP_CODIGO' in response_data:
                if (response_data['RSP_CODIGO'].isnumeric() and int(response_data['RSP_CODIGO']) == 0) \
                        or response_data['RSP_CODIGO'] == '':
                    import logging
                    logger = logging.getLogger(__name__)
                    logger.info(request.user.profile.get_full_name())
                    logger.info(response_data)
            else:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(request.user.profile.get_full_name())
                logger.error(response_data)
        except ParseError as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.exception(e)
            response_data = {'RSP_CODIGO': '-1', 'RSP_DESCRIPCION': "%s" % e}
            response_message = "%s" % e
            response_status = 400
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.exception(e)
            response_message = u"Error en applicación"
            response_status = 500
        finally:
            return self.get_response(response_message, response_data, response_status)

    def creation_ente(self, request, *args, **kwargs):
        from control.utils import creation_ente
        return self.control_action(request=request, control_function=creation_ente,
                                   name_control_function="creation_ente")

    def creation_cta_tar(self, request, *args, **kwargs):
        from control.utils import creation_cta_tar
        return self.control_action(request=request, control_function=creation_cta_tar,
                                   name_control_function="creation_cta_tar")

    def consulta_cuenta(self, request, *args, **kwargs):
        from control.utils import consulta_cuenta
        return self.control_action(request=request, control_function=consulta_cuenta,
                                   name_control_function="consulta_cuenta")

    def extrafinanciamientos(self, request, *args, **kwargs):
        from control.utils import extrafinanciamientos
        return self.control_action(request=request, control_function=extrafinanciamientos,
                                   name_control_function="extrafinanciamientos")

    def intrafinanciamientos(self, request, *args, **kwargs):
        from control.utils import intrafinanciamientos
        return self.control_action(request=request, control_function=intrafinanciamientos,
                                   name_control_function="intrafinanciamientos")

    def consulta_tarjetas(self, request, *args, **kwargs):
        from control.utils import consulta_tarjetas
        return self.control_action(request=request, control_function=consulta_tarjetas,
                                   name_control_function="consulta_tarjetas")

    def cambio_pin(self, request, *args, **kwargs):
        from control.utils import cambio_pin
        return self.control_action(request=request, control_function=cambio_pin,
                                   name_control_function="cambio_pin")

    def cambio_limites(self, request, *args, **kwargs):
        from control.utils import cambio_limites
        return self.control_action(request=request, control_function=cambio_limites,
                                   name_control_function="cambio_limites")

    def cambio_estatus_tdc(self, request, *args, **kwargs):
        from control.utils import cambio_estatus_tdc
        return self.control_action(request=request, control_function=cambio_estatus_tdc,
                                   name_control_function="cambio_estatus_tdc")

    def reposicion_tarjetas(self, request, *args, **kwargs):
        from control.utils import reposicion_tarjetas
        return self.control_action(request=request, control_function=reposicion_tarjetas,
                                   name_control_function="reposicion_tarjetas")

