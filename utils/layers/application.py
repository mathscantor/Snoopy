from utils.mappings import *


class ApplicationLayer:

    def __init__(self, application_type, application_data):

        if application_type == ApplicationType.UNKNOWN:
            print("Error in application type! Unable to do parsing in utils/layers/application.py!")
            print("Exiting...")
            exit(1)

    # TODO: parse http, https, pfcp
