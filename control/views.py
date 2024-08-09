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

    def creation_ente_sectorizacion(self, request, *args, **kwargs):
        from control.utils import creation_ente_sectorizacion
        return self.control_action(request=request, control_function=creation_ente_sectorizacion,
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

    def gestion_transacciones(self, request, *args, **kwargs):
        from control.utils import gestion_transacciones
        return self.control_action(request=request, control_function=gestion_transacciones,
                                   name_control_function="gestion_transacciones")

    def consulta_ente(self, request, *args, **kwargs):
        from control.utils import consulta_ente
        return self.control_action(request=request, control_function=consulta_ente,
                                   name_control_function="consulta_ente")

    def consulta_movimientos(self, request, *args, **kwargs):
        from control.utils import consulta_movimientos
        return self.control_action(request=request, control_function=consulta_movimientos,
                                   name_control_function="consulta_movimientos")

    def consulta_puntos(self, request, *args, **kwargs):
        from control.utils import consulta_puntos
        return self.control_action(request=request, control_function=consulta_puntos,
                                   name_control_function="consulta_puntos")

    def intra_extras(self, request, *args, **kwargs):
        from control.utils import intra_extras_mock
        return self.control_action(request=request, control_function=intra_extras_mock,
                                   name_control_function="intra_extras_mock")

    def consulta_intra_extra_f1(self, request, *args, **kwargs):
        from control.utils import consulta_intra_extra_f1
        return self.control_action(request=request, control_function=consulta_intra_extra_f1,
                                   name_control_function="consulta_intra_extra_f1")

    def consulta_transaciones_x_fecha(self, request, *args, **kwargs):
        from control.utils import consulta_transaciones_x_fecha
        return self.control_action(request=request, control_function=consulta_transaciones_x_fecha,
                                   name_control_function="consulta_txn_x_fecha_1")

    def consulta_cvv2(self, request, *args, **kwargs):
        from control.utils import consulta_cvv2
        return self.control_action(request=request, control_function=consulta_cvv2,
                                   name_control_function="consulta_cvv2")

    def consulta_estado_cuenta(self, request, *args, **kwargs):
        from control.utils import consulta_estado_cuenta
        return self.control_action(request=request, control_function=consulta_estado_cuenta,
                                   name_control_function="consulta_estado_cuenta")

    def alta_poliza(self, request, *args, **kwargs):
        from control.utils import alta_poliza
        return self.control_action(request=request, control_function=alta_poliza,
                                   name_control_function="alta_poliza")
