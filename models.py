from tornado.gen import coroutine
from random import choice
from datetime import datetime
class users:
    def __init__(self, email, user, name):
        self.email = email
        self.user = user
        self.name = name

class patient(users):
    @staticmethod
    @coroutine
    def make_appointment(db, user):
        resp = db.doctor.find({"$where": "this.plist.length<3"})
        listOfDoc = []
        while (yield resp.fetch_next):
            ele = resp.next_object()
            if 'qualifications' not in ele:
                ele['qualifications'] = None
            if 'description' not in ele:
                ele['description'] = None
            if 'name' not in ele:
                ele['name'] = ele['user']
            listOfDoc.append(
                dict(email=ele['email'], user=ele['user'], plist=ele['plist'], availability=ele['availability'],
                     qualifications=ele['qualifications'], description=ele['description'], name=ele['name']))
        print(user)
        if len(user['ap_details']) >= 3:
            print(user)
            return {'message': 'Maximum Appointments reached.', 'status_code': 400}
        if not listOfDoc:
            return {'message': 'Doctors Not Available.',
                    'status_code': 400}
        dbdoc = choice(listOfDoc)
        plist = [i['user'] for i in dbdoc['plist']]
        print(plist)
        while user['user'] in plist:
            listOfDoc.remove(dbdoc)
            if not listOfDoc:
                return {'message': 'Doctors Not Available.',
                        'status_code': 400}
            dbdoc = choice(listOfDoc)
            if not dbdoc['availability']:
                listOfDoc.remove(dbdoc)
                if not listOfDoc:
                    return {'message': 'Doctors Not Available.',
                            'status_code': 400}
                dbdoc = choice(listOfDoc)
            plist = [i['user'] for i in dbdoc['plist']]
        print(dbdoc)
        if 'name' not in user:
            user['name'] = user['user']

        user_details = dict(user=user['user'], name=user['name'], description=user['description'],
                            datetime=datetime.now().strftime("%d-%m-%Y %H:%M"))
        doctor_details = dict(user=dbdoc['user'], name=dbdoc['name'], qualifications=dbdoc['qualifications'],
                              datetime=datetime.now().strftime("%d-%m-%Y %H:%M"),description=dbdoc['description'])
        dbdoc['plist'].append(user_details)
        plist = dbdoc['plist']
        ap_list = user['ap_details']
        ap_list.append(doctor_details)
        db.patient.update({'user': user['user']}, {'$set': {'ap_details': ap_list}}, upsert=False)
        db.doctor.update({'user': dbdoc['user']}, {'$set': {'plist': plist}}, upsert=False)
        return {'status_code': 200, 'message': 'Updated Successfully.'}


