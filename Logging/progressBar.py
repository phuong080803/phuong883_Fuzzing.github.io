


def progressbar(iteration, total, prefix='', suffix='', length=100, fill='█', printEnd="\r"):
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}|', end=printEnd)
